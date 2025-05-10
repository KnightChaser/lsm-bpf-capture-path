// capture_path.c
#include "capture_path.skel.h"
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>

/* Shared structure between kernel and user space */
#define MAX_PATH_LEN 384
struct event {
    uint32_t pid;
    char path[MAX_PATH_LEN];
} __attribute__((packed));

static volatile sig_atomic_t stop;

static int handle_event(void *ctx, void *data, size_t sz) {
    const struct event *e = data;
    printf("[PID: %u] %s\n", e->pid, e->path);
    return 0;
}

static void sig_int(int signo) { stop = 1; }

int main(void) {
    struct capture_path_bpf *skel;
    struct ring_buffer *rb;
    int err;

    signal(SIGINT, sig_int);

    skel = capture_path_bpf__open();
    if (!skel)
        return 1;
    if ((err = capture_path_bpf__load(skel)))
        goto cleanup;
    if ((err = capture_path_bpf__attach(skel)))
        goto cleanup;

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL,
                          NULL);
    if (!rb) {
        err = -1;
        goto cleanup;
    }

    while (!stop)
        ring_buffer__poll(rb, 100);

cleanup:
    ring_buffer__free(rb);
    capture_path_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}
