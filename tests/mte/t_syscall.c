// System calls on watched buffers. The kernel reads and writes user memory
// with the caller's pointer tag; on an armed granule that would be fatal, so
// the interposed wrappers run the call against a bounce buffer and report
// the access as made "by the kernel".
#include "mt.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>

static void expect_sys(const char *name, unsigned access, long off, unsigned size) {
    const mt_event *e = mt_last();
    if (mt_count() != 1 || strcmp(e->syscall, name) || e->access != access || e->offset != off || e->size != size)
        fprintf(stderr, "  %s: %d events, last: syscall=%s access=%u off=%lld size=%u\n", name, mt_count(), e->syscall, e->access,
                (long long)e->offset, e->size);
    CHECK_EQ(mt_count(), 1);
    CHECK(e->flags & TAGWATCH_EV_SYSCALL);
    CHECK(!strcmp(e->syscall, name));
    CHECK(e->access == access);
    CHECK_EQ(e->offset, off);
    CHECK_EQ(e->size, size);
    CHECK(e->tid == mt_tid());
    CHECK(e->nframes >= 1);
    mt_reset();
}

int main(void) {
    mt_start("syscall");
    char *buf = tagwatch_alloc_watched(64, "iobuf");
    char plain[64], got[64];
    int fds[2];
    CHECK(pipe(fds) == 0);

    // read(): the kernel writes into the watched buffer.
    CHECK(write(fds[1], "hello world", 11) == 11);
    CHECK_EQ(mt_count(), 0); // unwatched source: not reported
    CHECK(read(fds[0], buf, 64) == 11);
    expect_sys("read", TAGWATCH_WRITE, 0, 11);
    tagwatch_peek(got, buf, 11);
    CHECK(memcmp(got, "hello world", 11) == 0);

    // write(): the kernel reads the watched buffer.
    CHECK(write(fds[1], buf + 6, 5) == 5);
    expect_sys("write", TAGWATCH_READ, 6, 5);
    CHECK(read(fds[0], plain, 64) == 5 && memcmp(plain, "world", 5) == 0);
    CHECK_EQ(mt_count(), 0);

    // Errors pass through untouched and report nothing.
    errno = 0;
    CHECK(read(-1, buf, 8) == -1 && errno == EBADF);
    CHECK(write(-1, buf, 8) == -1 && errno == EBADF);
    CHECK_EQ(mt_count(), 0);

    // pread/pwrite on a file.
    char path[] = "/tmp/tagwatch-test.XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    unlink(path);
    tagwatch_poke(buf, "0123456789abcdef", 16);
    CHECK(pwrite(fd, buf, 16, 0) == 16);
    expect_sys("pwrite", TAGWATCH_READ, 0, 16);
    CHECK(pread(fd, buf + 32, 8, 4) == 8);
    expect_sys("pread", TAGWATCH_WRITE, 32, 8);
    tagwatch_peek(got, buf + 32, 8);
    CHECK(memcmp(got, "456789ab", 8) == 0);
    close(fd);

    // send/recv on a socket pair.
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    CHECK(send(sv[0], buf, 10, 0) == 10);
    expect_sys("send", TAGWATCH_READ, 0, 10);
    CHECK(recv(sv[1], buf + 48, 10, 0) == 10);
    expect_sys("recv", TAGWATCH_WRITE, 48, 10);

    // stdio, large enough to bypass the FILE buffer.
    FILE *f = tmpfile();
    CHECK(f != NULL);
    CHECK(fwrite(buf, 1, 64, f) == 64);
    expect_sys("fwrite", TAGWATCH_READ, 0, 64);
    rewind(f);
    memset(plain, 0, sizeof plain);
    tagwatch_poke(buf, plain, 64);
    CHECK(fread(buf, 1, 64, f) == 64);
    expect_sys("fread", TAGWATCH_WRITE, 0, 64);
    tagwatch_peek(got, buf, 16);
    CHECK(memcmp(got, "0123456789abcdef", 16) == 0);
    fclose(f);

    // A call whose buffer only partly overlaps the watch is clipped to it.
    char *block = tagwatch_alloc(128);
    CHECK(tagwatch_watch(block + 32, 16, "middle") > 0);
    memset(plain, 'x', sizeof plain);
    CHECK(write(sv[0], plain, 64) == 64);
    CHECK(read(sv[1], block, 64) == 64);
    expect_sys("read", TAGWATCH_WRITE, 0, 16);
    tagwatch_peek(got, block, 64);
    CHECK(got[0] == 'x' && got[40] == 'x' && got[63] == 'x');
    // ...and one that does not touch it goes straight to the kernel.
    CHECK(write(sv[0], plain, 16) == 16);
    CHECK(read(sv[1], block + 64, 16) == 16);
    CHECK_EQ(mt_count(), 0);

    tagwatch_stats st;
    tagwatch_get_stats(&st);
    CHECK_EQ(st.syscalls, 9);
    CHECK_EQ(st.violations, 0);
    close(fds[0]), close(fds[1]), close(sv[0]), close(sv[1]);
    return mt_done();
}
