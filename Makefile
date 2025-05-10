# ---- basic paths ------------------------------------------------
BPF_SRC        := capture_path.bpf.c
BPF_OBJ        := $(BPF_SRC:.c=.o)
SKEL_HEADER    := capture_path.skel.h
USER_BIN       := capture_path

# user-space sources
USER_SRCS      := capture_path.c uid_gid_lookup.c
USER_OBJS      := $(USER_SRCS:.c=.o)

CLANG          ?= clang
BPFOOL         ?= bpftool
CC             ?= gcc

CFLAGS_BPF     ?= -O2 -g -target bpf
CFLAGS_USER    ?= -O2 -g
LDFLAGS_USER   ?= -lelf -lbpf
PKG_INCLUDES   := -I/usr/include/bpf

# ---- default target ---------------------------------------------
all: vmlinux.h $(BPF_OBJ) $(SKEL_HEADER) $(USER_BIN)

# 1. generate vmlinux.h once
vmlinux.h:
	$(BPFOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# 2. compile the kernel program
$(BPF_OBJ): $(BPF_SRC) vmlinux.h
	$(CLANG) $(CFLAGS_BPF) -c $< -o $@

# 3. generate skeleton
$(SKEL_HEADER): $(BPF_OBJ)
	$(BPFOOL) gen skeleton $< > $@

# 4a. build user-space object files
%.o: %.c
	$(CC) $(CFLAGS_USER) $(PKG_INCLUDES) -c $< -o $@

# 4b. link the final loader binary
$(USER_BIN): $(USER_OBJS) $(SKEL_HEADER)
	$(CC) $(CFLAGS_USER) $(PKG_INCLUDES) $^ -o $@ $(LDFLAGS_USER)

# ---- housekeeping -----------------------------------------------
clean:
	rm -f $(USER_BIN) \
	      $(BPF_OBJ) $(SKEL_HEADER) vmlinux.h \
	      $(USER_OBJS)

