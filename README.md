
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

NOTE
--------------------

### Caution (for newcomers like me)

* **“Sleepable” BPF programs are allowed to call helpers (and kfuncs) that might block or schedule---such as `bpf_d_path()`---so the verifier demands you mark them with the flag `BPF_F_SLEEPABLE`**.
  * A **sleepable BPF program**  runs in a context where it can **legitimately block**, call into the memory allocator, look up file names, etc. When such blocking is possible the verifier forces you to opt‑in by setting **`BPF_F_SLEEPABLE`**; otherwise helpers marked **KF_SLEEPABLE**  are rejected.
  * Non‑sleepable program types (e.g., **kprobes**, XDP) still run in hard‑IRQ or preempt‑disabled contexts and therefore cannot call helpers such as `bpf_d_path()` or `bpf_copy_from_user()`  that may sleep.
* BPF programs permitted to call helpers/kfuncs that can **block**; must load with `BPF_F_SLEEPABLE`. If you omit `.s`---`SEC("lsm/file_open")`(Refer to `capture_path.bpf.c`)---libbpf still generates an LSM program, but without the sleepable flag, so helpers like `bpf_d_path()` (Which is "sleepable") would fail to load.

### Useful references

* [BPF Kernel Functions (kfuncs)](https://docs.kernel.org/bpf/kfuncs.html)
* [kfuncs for BPF LSM use cases (Presentation)](https://lpc.events/event/18/contributions/1940/attachments/1438/3389/kfuncs%20for%20BPF%20LSM%20Use%20Cases.v4.pdf?utm_source=chatgpt.com)
* [Eunomia-bpf's LSM example](https://eunomia.dev/en/tutorials/19-lsm-connect/)
* Master list of hookable LSM functions (**`include/linux/lsm_hooks.h`**  in your kernel tree): [Google Android Source](https://android.googlesource.com/kernel/common/%2B/6be064d42c55/include/linux/lsm_hooks.h) or [GitHub Linux source tree (`lsm_hook_defs.h`)](https://github.com/torvalds/linux/blob/master/include/linux/lsm_hook_defs.h)
