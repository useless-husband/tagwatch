// Target for the CLI tests: a linked list, a global counter, a second
// thread and a large allocation. It knows nothing about tagwatch.
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct node {
    struct node *next;
    long key;
    char name[24];
};

long g_counter;
long g_other;
static volatile long g_static_table[4];

__attribute__((noinline)) static struct node *make_node(long k) {
    struct node *n = malloc(sizeof *n);
    n->key = k;
    n->next = NULL;
    snprintf(n->name, sizeof n->name, "n%ld", k);
    return n;
}

__attribute__((noinline)) static void bump(void) { g_counter++; }

static void *worker(void *arg) {
    struct node *n = arg;
    for (volatile int i = 0; i < 3; i++) n->key += 1;
    return NULL;
}

int main(int argc, char **argv) {
    alarm(60);
    struct node *head = NULL;
    for (int i = 0; i < 4; i++) {
        struct node *n = make_node(i);
        n->next = head;
        head = n;
    }
    long sum = 0;
    for (struct node *n = head; n; n = n->next) sum += n->key;
    for (int i = 0; i < 3; i++) bump();
    g_other = 5;
    g_static_table[2] = 7;
    pthread_t t;
    pthread_create(&t, NULL, worker, head);
    pthread_join(t, NULL);
    char *volatile big_slot = malloc(100000); // volatile: keep the allocation in optimised builds
    char *big = big_slot;
    memset(big, 1, 100000);
    long bigsum = 0;
    for (int i = 0; i < 100000; i += 4096) bigsum += big[i];
    free(big);
    while (head) {
        struct node *n = head->next;
        free(head);
        head = n;
    }
    printf("sum=%ld counter=%ld big=%ld table=%ld\n", sum, g_counter, bigsum, g_static_table[2]);
    if (argc > 1 && !strcmp(argv[1], "addr")) printf("g_counter@%p\n", (void *)&g_counter);
    return 0;
}
