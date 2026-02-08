CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

# 获取内核架构
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# 编译 flags
CFLAGS := -O2 -g -Wall
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_$(ARCH) $(CFLAGS)

# 默认目标
all: minimal.skel.h minimal

# 生成 BPF 目标文件
%.bpf.o: %.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# 生成骨架头文件
%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# 编译用户空间程序
minimal: minimal.c minimal.skel.h
	$(CC) $(CFLAGS) -c minimal.c -o minimal.o
	$(CC) minimal.o -lelf -lz -lbpf -o minimal

clean:
	rm -f *.o *.skel.h minimal

.PHONY: all clean
