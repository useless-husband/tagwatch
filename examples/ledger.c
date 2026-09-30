// ledger: a small program with a planted memory-corruption bug, used as the
// worked example in the README.
//
// Every customer record has a 16-byte nickname followed by a credit limit.
// set_nick() copies the nickname without checking its length, so a long
// nickname silently overwrites the first bytes of credit_limit *inside the
// same heap object*. Nothing crashes. AddressSanitizer and MTE itself do not
// see it either: both only police the boundaries of an allocation, and this
// write never leaves one. The only symptom is an audit at the end that finds
// a few credit limits changed.
//
// Build:  make examples
// Run:    build/examples/ledger
// Find:   build/tagwatch run -q -w -a caller=customer_new,off=16,len=8,label=credit_limit -- build/examples/ledger
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CUSTOMERS 500
#define DEFAULT_LIMIT 5000

struct customer {
    char nick[16];
    long credit_limit;
    long balance;
    int id;
};

static struct customer *book[CUSTOMERS];
static unsigned long declined;

__attribute__((noinline)) static struct customer *customer_new(int id) {
    struct customer *c = malloc(sizeof *c);
    if (!c) abort();
    memset(c->nick, 0, sizeof c->nick);
    c->credit_limit = DEFAULT_LIMIT;
    c->balance = 0;
    c->id = id;
    return c;
}

__attribute__((noinline)) static void set_nick(struct customer *c, const char *nick) {
    memcpy(c->nick, nick, strlen(nick) + 1); // BUG: nick may be longer than c->nick
}

__attribute__((noinline)) static void import_customers(void) {
    char name[64];
    for (int i = 0; i < CUSTOMERS; i++) {
        book[i] = customer_new(i);
        // Most imported nicknames are short. A handful are not.
        if (i % 97 == 96) snprintf(name, sizeof name, "customer-number-%d", i);
        else snprintf(name, sizeof name, "user%d", i);
        set_nick(book[i], name);
    }
}

__attribute__((noinline)) static void charge(struct customer *c, long amount) {
    if (c->balance + amount <= c->credit_limit) c->balance += amount;
    else declined++;
}

int main(void) {
    import_customers();
    unsigned long long rng = 88172645463325252ull; // fixed seed: every run is identical
    for (int i = 0; i < 20000; i++) {
        rng ^= rng << 13, rng ^= rng >> 7, rng ^= rng << 17;
        charge(book[rng % CUSTOMERS], (long)(rng >> 40) % 400);
    }
    int bad = 0, first = -1;
    for (int i = 0; i < CUSTOMERS; i++)
        if (book[i]->credit_limit != DEFAULT_LIMIT) {
            if (first < 0) first = i;
            bad++;
        }
    printf("ledger: %d customers, %lu charges declined\n", CUSTOMERS, declined);
    if (bad) {
        printf("ledger: AUDIT FAILED: %d customers have a credit limit other than %d (first: #%d, limit %ld)\n", bad, DEFAULT_LIMIT,
               first, book[first]->credit_limit);
        return 1;
    }
    printf("ledger: audit passed\n");
    return 0;
}
