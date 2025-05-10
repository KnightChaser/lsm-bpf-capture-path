// capture_path.c
#include "capture_path.skel.h"
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

/* Custom UID cache */
static struct {
    uid_t uid;
    char name[NAME_LEN];
    bool valid;
} uid_cache[UID_CACHE_SIZE] = {0};

/* Return pointer to a null-terminated string in cache */
static const char *uid_to_name(uid_t uid) {
    /* cache lookup */
    for (size_t i = 0; i < UID_CACHE_SIZE; i++) {
        if (uid_cache[i].valid && uid_cache[i].uid == uid) {
            return uid_cache[i].name;
        }
    }

    /* Not found -> resolve */
    struct passwd *pw = getpwuid(uid);
    const char *name = pw ? pw->pw_name : NULL;
    if (!name) {
        return "unknown";
    }

    /* cache the result */
    for (size_t i = 0; i < UID_CACHE_SIZE; i++) {
        if (!uid_cache[i].valid) {
            uid_cache[i].valid = true;
            uid_cache[i].uid = uid;
            strncpy(uid_cache[i].name, name, NAME_LEN - 1);
            uid_cache[i].name[NAME_LEN - 1] = '\0';
            break;
        }
    }

    return name;
}

/* Custom GID cache */
static struct {
    gid_t gid;
    char name[NAME_LEN];
    bool valid;
} gid_cache[GID_CACHE_SIZE] = {0};

/* Return pointer to a null-terminated string in cache */
static const char *gid_to_name(gid_t gid) {
    /* cache lookup */
    for (size_t i = 0; i < GID_CACHE_SIZE; i++) {
        if (gid_cache[i].valid && gid_cache[i].gid == gid) {
            return gid_cache[i].name;
        }
    }

    /* Not found -> resolve */
    struct group *gr = getgrgid(gid);
    const char *name = gr ? gr->gr_name : NULL;
    if (!name) {
        return "unknown";
    }

    /* cache the result */
    for (size_t i = 0; i < GID_CACHE_SIZE; i++) {
        if (!gid_cache[i].valid) {
            gid_cache[i].valid = true;
            gid_cache[i].gid = gid;
            strncpy(gid_cache[i].name, name, NAME_LEN - 1);
            gid_cache[i].name[NAME_LEN - 1] = '\0';
            break;
        }
    }

    return name;
}

static int handle_event(void *ctx, void *data, size_t sz) {
    const struct event *e = data;

    const char *user = uid_to_name(e->uid);
    const char *group = gid_to_name(e->gid);

    printf("[PID %u] Permission=%s(%u):%s(%u) inode=%" PRIu64 " size=%" PRIu64
           "(Bytes) mode=%#o filepath=%s\n",
           e->pid, user, e->uid, group, e->gid, e->inode, e->size,
           e->mode & 07777, e->path);
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
