BPF_TOOL := /usr/lib/linux-tools/6.8.0-110-generic/bpftool
CC := clang
CXX := g++
CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86

all: kwatch

src/kwatch.bpf.o: src/kwatch.bpf.c
	$(CC) $(BPF_CFLAGS) -c $< -o $@

src/kwatch.skel.h: src/kwatch.bpf.o
	$(BPF_TOOL) gen skeleton $< > $@

kwatch: src/kwatch.cpp src/kwatch.skel.h
	$(CXX) $(CFLAGS) src/kwatch.cpp -lbpf -lelf -lz -o kwatch

clean:
	rm -f src/*.o src/*.skel.h kwatch

.PHONY: all clean
