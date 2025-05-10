// capture_path.bpf.c
#define MAX_PATH_LEN 384
#define MAX_PROCESS_NAME_LEN 32

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Ring buffer event */
struct event {
    u32 pid;
    u32 file_opener_uid; /* Who opened the file (UID) */
    u32 file_opener_gid; /* Who opened the file (GID) */
    u32 file_owner_uid;  /* Who owns the file (UID) */
    u32 file_owner_gid;  /* Who owns the file (GID) */
    u32 mode;            /* permission bits + type bits */
    u64 inode;
    u64 size;
    char process_name[MAX_PROCESS_NAME_LEN];
    char path[MAX_PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1 MiB */
} events SEC(".maps");

static __always_inline int get_path_full(struct file *f, char *buf, int len) {
#ifdef bpf_path_d_path
    /* kernel >= 6.8 */
    return bpf_path_d_path(&f->f_path, buf, len);
#else
    /* Automatic fallback to the older kernel */
    return bpf_d_path(&f->f_path, buf, len);
#endif
}

/* Sleepable LSM hook -> helper allowed */
SEC("lsm.s/file_open")
int BPF_PROG(capture_open, struct file *file) {
    struct event *e;
    struct inode *inode;
    int ret;

    /* Reserve space */
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    /* Obtain process information */
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->process_name, sizeof(e->process_name));

    /* Obtain process UID/GID */
    u64 uid_gid = bpf_get_current_uid_gid();
    e->file_opener_uid = uid_gid & 0xFFFFFFFF;
    e->file_opener_gid = uid_gid >> 32;

    /* Obtain file information */
    inode = BPF_CORE_READ(file, f_inode);
    e->file_owner_uid = BPF_CORE_READ(inode, i_uid.val);
    e->file_owner_gid = BPF_CORE_READ(inode, i_gid.val);
    e->mode = BPF_CORE_READ(inode, i_mode);
    e->inode = BPF_CORE_READ(inode, i_ino);
    e->size = BPF_CORE_READ(inode, i_size);

    /* Grab full path safely */
    ret = get_path_full(file, e->path, sizeof(e->path));
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0; /* 0 = allow open() to proceed */
}

char LICENSE[] SEC("license") = "GPL";
