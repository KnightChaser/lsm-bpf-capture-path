// capture_path.c
#include "capture_path.skel.h"
#include <bpf/libbpf.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/utsname.h>

/* Shared structure between kernel and user space */
#define MAX_PATH_LEN 384
struct event {
    uint32_t pid;
    uint32_t uid;
    uint32_t gid;
    uint32_t mode; /* permission bits + type bits */
    uint64_t inode;
    uint64_t size;
    char path[MAX_PATH_LEN];
} __attribute__((packed));

static volatile sig_atomic_t stop;

static int handle_event(void *ctx, void *data, size_t sz) {
    const struct event *e = data;
    printf("[PID %u UID %u GID %u] ino=%" PRIu64 " size=%" PRIu64
           " mode=%#o  %s\n",
           e->pid, e->uid, e->gid, e->inode, e->size, e->mode & 07777, e->path);
    return 0;
}

static void sig_int(int signo) { stop = 1; }

int main(void) {
    struct utsname u;
    uname(&u);
    printf("Kernel: %s\n", u.release);

    struct capture_path_bpf *skel = capture_path_bpf__open();
    if (!skel) {
        return 1;
    }

    if (capture_path_bpf__load(skel) || capture_path_bpf__attach(skel)) {
        fprintf(stderr, "load/attach failed\n");
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                                              handle_event, NULL, NULL);
    if (!rb) {
        perror("ring_buffer__new");
        return 1;
    }

    signal(SIGINT, sig_int);
    while (!stop)
        ring_buffer__poll(rb, 100);

    ring_buffer__free(rb);
    capture_path_bpf__destroy(skel);
    return 0;
}
