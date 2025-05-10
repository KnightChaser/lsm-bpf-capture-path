# ---- basic paths ------------------------------------------------
BPF_SRC        := capture_path.bpf.c
BPF_OBJ        := $(BPF_SRC:.c=.o)
SKEL_HEADER    := capture_path.skel.h
USER_BIN       := capture_path

CLANG          ?= clang
BPFOOL         ?= bpftool
CFLAGS_USER    ?= -O2 -g
CFLAGS_BPF     ?= -O2 -g -target bpf
LDFLAGS_USER   ?= -lelf -lbpf

# ---- rules ------------------------------------------------------
all: $(USER_BIN)

# 1. generate vmlinux.h once
vmlinux.h:
	$(BPFOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# 2. compile the kernel program
$(BPF_OBJ): $(BPF_SRC) vmlinux.h
	$(CLANG) $(CFLAGS_BPF) -c $< -o $@

# 3. generate skeleton
$(SKEL_HEADER): $(BPF_OBJ)
	$(BPFOOL) gen skeleton $< > $@

# 4. build user loader
$(USER_BIN): capture_path.c $(SKEL_HEADER)
	$(CC) $(CFLAGS_USER) $< -I/usr/include/bpf -o $@ $(LDFLAGS_USER)

clean:
	rm -rf $(USER_BIN)
	rm -rf $(BPF_OBJ)
	rm -rf $(SKEL_HEADER)
	rm -rf vmlinux.h
