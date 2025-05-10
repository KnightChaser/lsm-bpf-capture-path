// capture_path.c
#include "capture_path.skel.h"
#include "uid_gid_lookup.h"
#include <bpf/libbpf.h>
#include <grp.h>
#include <inttypes.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/utsname.h>

/* cache sizes—you can bump these if you expect more distinct users/groups */
#define UID_CACHE_SIZE 64
#define GID_CACHE_SIZE 64
#define NAME_LEN 32

/* Shared structure between kernel and user space */
#define MAX_PATH_LEN 384
#define MAX_PROCESS_NAME_LEN 32
struct event {
    uint32_t pid;
    uint32_t file_opener_uid; /* Who opened the file (UID) */
    uint32_t file_opener_gid; /* Who opened the file (GID) */
    uint32_t file_owner_uid;  /* Who owns the file (UID) */
    uint32_t file_owner_gid;  /* Who owns the file (GID) */
    uint32_t mode;            /* permission bits + type bits */
    uint64_t inode;
    uint64_t size;
    char process_name[MAX_PROCESS_NAME_LEN];
    char path[MAX_PATH_LEN];
} __attribute__((packed));

static volatile sig_atomic_t stop;

static int handle_event(void *ctx, void *data, size_t sz) {
    const struct event *e = data;

    const char *file_opener_uid_name = uid_to_name(e->file_opener_uid);
    const char *file_opener_gid_name = gid_to_name(e->file_opener_gid);
    const char *file_owner_uid_name = uid_to_name(e->file_owner_uid);
    const char *file_owner_gid_name = gid_to_name(e->file_owner_gid);

    printf("[PID %u] "                                   // NOLINT
           "File opener=%s(%u):%s(%u), "                 // NOLINT
           "File owner=%s(%u):%s(%u), "                  // NOLINT
           "inode=%" PRIu64 ", size=%" PRIu64            // NOLINT
           "Bytes, mode=%#o, program=%s, filepath=%s\n", // NOLINT
           e->pid,                                       // NOLINT
           file_opener_uid_name, e->file_opener_uid,     // NOLINT
           file_opener_gid_name, e->file_opener_gid,     // NOLINT
           file_owner_uid_name, e->file_owner_uid,       // NOLINT
           file_owner_gid_name, e->file_owner_gid,       // NOLINT
           e->inode, e->size, e->mode & 07777,           // NOLINT
           e->process_name, e->path);                    // NOLINT
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
