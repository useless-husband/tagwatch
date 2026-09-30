// C++ target: objects from operator new, accessed through methods.
#include <cstdio>
#include <memory>
#include <unistd.h>
#include <vector>

struct Account {
    long id;
    long balance;
    long history[4];
    void deposit(long n) __attribute__((noinline)) { balance += n; }
};

__attribute__((noinline)) static Account *open_account(long id) { return new Account{id, 0, {0, 0, 0, 0}}; }

int main() {
    alarm(60);
    std::vector<Account *> all;
    for (long i = 0; i < 3; i++) all.push_back(open_account(i));
    for (int round = 0; round < 5; round++)
        for (auto *a : all) a->deposit(10);
    long total = 0;
    for (auto *a : all) total += a->balance;
    std::printf("total=%ld\n", total);
    for (auto *a : all) delete a;
    return 0;
}
