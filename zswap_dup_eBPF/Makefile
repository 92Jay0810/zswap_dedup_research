# Makefile for zswap_dedup eBPF tool
# 適用 Ubuntu 24.04，kernel 6.8
# Hook: kprobe/zswap_store（kernel 6.8 已無 zswap_compress 符號）

# ============================================================
# 工具鏈設定
# ============================================================
CLANG      ?= clang
BPFTOOL    ?= bpftool
CC         ?= gcc

ARCH       := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KERNEL_VER := $(shell uname -r)
KERNEL_SRC ?= /lib/modules/$(KERNEL_VER)/build

VMLINUX_H  ?= vmlinux.h

# ============================================================
# 編譯旗標
# ============================================================
BPF_CFLAGS := -g -O2 -target bpf                \
              -D__TARGET_ARCH_$(ARCH)            \
              -I.                                \
              -I/usr/include/$(shell uname -m)-linux-gnu \
              -Wall -Wno-unused-variable

USER_CFLAGS := -g -O2 -Wall                     \
               -I.                               \
               -I/usr/include/bpf

USER_LDFLAGS := -lbpf -lelf -lz

# ============================================================
# 預設目標
# ============================================================
.PHONY: all clean vmlinux install-deps check-zswap check-hook

all: zswap_dedup

# ============================================================
# Step 1: 生成 vmlinux.h
# ============================================================
vmlinux.h:
	@echo "[1/4] Generating vmlinux.h from running kernel BTF..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)
	@echo "      Done: $(VMLINUX_H)"

# ============================================================
# Step 2: 編譯 BPF object
# ============================================================
zswap_dedup.bpf.o: zswap_dedup.bpf.c $(VMLINUX_H)
	@echo "[2/4] Compiling BPF program..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "      Done: $@"

# ============================================================
# Step 3: 生成 BPF skeleton header
# ============================================================
zswap_dedup.skel.h: zswap_dedup.bpf.o
	@echo "[3/4] Generating BPF skeleton..."
	$(BPFTOOL) gen skeleton $< > $@
	@echo "      Done: $@"

# ============================================================
# Step 4: 編譯 userspace loader
# ============================================================
zswap_dedup: zswap_dedup.c zswap_dedup.skel.h
	@echo "[4/4] Compiling userspace loader..."
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)
	@echo "      Done: $@"
	@echo ""
	@echo "Build successful! Run with: sudo ./zswap_dedup"

# ============================================================
# 確認 hook 點存在
# ============================================================
check-hook:
	@echo "=== Checking hook symbol ==="
	@echo -n "zswap_store: "
	@sudo grep ' [tT] zswap_store$$' /proc/kallsyms \
		&& echo "OK" || echo "NOT FOUND - zswap may not be loaded"
	@echo ""
	@echo "=== Note: zswap_compress is intentionally absent in kernel 6.8 ==="
	@echo "    It has been inlined into zswap_store."
	@sudo grep 'zswap_compress' /proc/kallsyms 2>/dev/null \
		|| echo "    (confirmed: no zswap_compress symbol)"

# ============================================================
# 確認 zswap 狀態
# ============================================================
check-zswap:
	@echo "=== zswap status ==="
	@cat /sys/module/zswap/parameters/enabled 2>/dev/null \
		|| echo "zswap module not loaded"
	@echo ""
	@echo "=== swap status ==="
	@swapon --show
	@echo ""
	@echo "=== zswap stats ==="
	@sudo ls /sys/kernel/debug/zswap/ 2>/dev/null \
		&& sudo grep . /sys/kernel/debug/zswap/* \
		|| echo "No zswap debug fs (try: sudo mount -t debugfs debugfs /sys/kernel/debug)"
	@echo ""
	@echo "=== vmemmap / page_offset (for BPF constant validation) ==="
	@sudo grep -E 'page_offset_base|vmemmap_base' /proc/kallsyms 2>/dev/null \
		|| echo "    (symbols hidden - running kernel may have these fixed at compile time)"

# ============================================================
# 安裝必要套件（Ubuntu 24.04）
# ============================================================
install-deps:
	@echo "Installing dependencies for Ubuntu 24.04..."
	sudo apt-get update
	sudo apt-get install -y \
		clang \
		llvm \
		libbpf-dev \
		linux-tools-common \
		linux-tools-$(shell uname -r) \
		linux-headers-$(shell uname -r) \
		bpftool \
		pkg-config \
		libelf-dev \
		zlib1g-dev \
		stress-ng
	@echo "Done."

# ============================================================
# 清理
# ============================================================
clean:
	rm -f zswap_dedup zswap_dedup.bpf.o zswap_dedup.skel.h vmlinux.h
