# `lsm-bpf-capture-path`

This mini‑project shows how to capture every `file_open` event in the Linux kernel and print the **full pathname** from user space. On kernels **>= 6.8** it uses the safer `bpf_path_d_path()` kfunc; on older kernels it transparently falls back to `bpf_d_path()`.

```c
// (A function defined inside capture_path.bpf.c
static __always_inline int get_path_full(struct file *f, char *buf, int len) {
#ifdef bpf_path_d_path
    /* kernel >= 6.8 */
    return bpf_path_d_path(&f->f_path, buf, len);
#else
    /* Automatic fallback to the older kernel */
    return bpf_d_path(&f->f_path, buf, len);
#endif
}
```

Prerequisites
-------------

* **Kernel 5.13 or newer** compiled with  `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_LSM=y`, `CONFIG_SECURITY=y` and writeable hooks.  Kernel >= 6.8 enables the safer `bpf_path_d_path()` kfunc. (If not supported, `bpf_d_path()` will be used instead. *(Note: It looks like `bpf_path_d_path()` may not be supported in Linux with newer version. In my case, I'm using Ubuntu 22.04 LTS with kernel 6.11.0-25-generic, but I couldn't find `bpf_path_d_path` in vmlinux symbol. Any helps about this will be highly appreciated.)*
* LLVM/Clang 12+, libbpf 1.5+, bpftool (usually in `linux-tools-$(uname -r)`).
* A distro that lets you pass custom kernel parameters (GRUB, systemd‑boot,…).

Enabling the BPF LSM
--------------------

1. Edit `/etc/default/grub` and append  `lsm=lockdown,capability,bpf` to `GRUB_CMDLINE_LINUX`.
2. `sudo update-grub` (or `grub-mkconfig -o /boot/grub/grub.cfg` on Arch).
3. Reboot and verify:  

```bash
cat /sys/kernel/security/lsm
# lockdown,capability,bpf
```

If bpf is not listed, the hook chain will never reach the program.
