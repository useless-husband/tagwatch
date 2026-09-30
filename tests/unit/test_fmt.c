#include "../../src/fmt.h"
#include "t.h"

int main(void) {
    char s[64];
    tw_buf b;

    tw_buf_init(&b, s, sizeof s);
    tw_put_dec(&b, 0);
    tw_put_char(&b, ' ');
    tw_put_dec(&b, 18446744073709551615ull);
    CHECK_STR(s, "0 18446744073709551615");

    tw_buf_init(&b, s, sizeof s);
    tw_put_sdec(&b, INT64_MIN);
    CHECK_STR(s, "-9223372036854775808");

    tw_buf_init(&b, s, sizeof s);
    tw_put_hex(&b, 0);
    tw_put_char(&b, ' ');
    tw_put_hex(&b, 0xdeadbeefcafef00dull);
    CHECK_STR(s, "0x0 0xdeadbeefcafef00d");

    tw_buf_init(&b, s, sizeof s);
    tw_put_fmt(&b, "%s=%d %u %x %llu %lld %p %c%%", "k", -5, 7u, 255u, 1ull << 40, -3ll, (void *)0x10, 'z');
    CHECK_STR(s, "k=-5 7 ff 1099511627776 -3 0x10 z%");

    tw_buf_init(&b, s, sizeof s);
    tw_put_json_str(&b, "a\"b\\c\n\t\x01");
    CHECK_STR(s, "\"a\\\"b\\\\c\\n\\t\\u0001\"");

    // Truncation never writes past the buffer and always leaves a NUL.
    char small[8];
    memset(small, 'X', sizeof small);
    tw_buf_init(&b, small, 5);
    tw_put_str(&b, "abcdefghij");
    CHECK(b.truncated);
    CHECK_STR(small, "abcd");
    CHECK(small[5] == 'X');
    tw_buf_init(&b, small, 0);
    tw_put_str(&b, "abc");
    CHECK(b.truncated && b.len == 0);

    uint64_t v;
    CHECK(tw_parse_u64("123", 3, &v) == 0 && v == 123);
    CHECK(tw_parse_u64("0x1F", 4, &v) == 0 && v == 31);
    CHECK(tw_parse_u64("4k", 2, &v) == 0 && v == 4096);
    CHECK(tw_parse_u64("2M", 2, &v) == 0 && v == 2u << 20);
    CHECK(tw_parse_u64("18446744073709551615", 20, &v) == 0 && v == UINT64_MAX);
    CHECK(tw_parse_u64("18446744073709551616", 20, &v) != 0);
    CHECK(tw_parse_u64("0xffffffffffffffff", 18, &v) == 0 && v == UINT64_MAX);
    CHECK(tw_parse_u64("0x10000000000000000", 19, &v) != 0);
    CHECK(tw_parse_u64("", 0, &v) != 0);
    CHECK(tw_parse_u64("0x", 2, &v) != 0);
    CHECK(tw_parse_u64("12a", 3, &v) != 0);
    CHECK(tw_parse_u64("k", 1, &v) != 0);
    CHECK(tw_parse_u64("4kk", 3, &v) != 0);
    CHECK(tw_parse_u64("0x4k", 4, &v) != 0);
    CHECK(tw_parse_u64("17592186044416m", 15, &v) != 0); // overflow through the suffix

    // Round trip: every value printed in decimal or hex parses back.
    uint64_t st = t_seed(0x7461677761746368ull);
    for (int i = 0; i < 20000; i++) {
        uint64_t x = t_rand(&st) >> (t_rand(&st) & 63);
        tw_buf_init(&b, s, sizeof s);
        if (i & 1) tw_put_hex(&b, x); else tw_put_dec(&b, x);
        CHECK(tw_parse_u64(s, b.len, &v) == 0 && v == x);
    }
    return t_done("fmt");
}
