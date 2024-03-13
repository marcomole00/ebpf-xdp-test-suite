# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
SHELL := /bin/bash
PKG_CONFIG := pkg-config

LIBBPF_SRC := $(abspath ./lib/libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
LIBBPF_PKGCONFIG := $(abspath $(OUTPUT)/pkgconfig)

BPFTOOL_SRC := $(abspath ./lib/bpftool/src)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool

LIBLOG_OBJ := $(abspath $(OUTPUT)/liblog.o)
LIBLOG_SRC := $(abspath ./lib/liblog/src/log.c)
LIBLOG_HDR := $(abspath ./lib/liblog/src/)

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(OUTPUT) -I./lib/libbpf/include/uapi -I$(LIBLOG_HDR)
CFLAGS := -g -Wall -DLOG_USE_COLOR
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS) -lrt -ldl -lpthread -lm

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

APPS := xdp_test

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	rm -rf $(OUTPUT) $(APPS)

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	@echo "=== Building libbpf"
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1    \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)	\
		    INCLUDEDIR= LIBDIR= UAPIDIR=              \
		    install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	@echo "=== Building bpftool"
	$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Build liblog
$(LIBLOG_OBJ):
	@echo "=== Building liblog"
	$(CC) $(CFLAGS) $(INCLUDES) -c $(LIBLOG_SRC) -o $@

# Build BPF code
$(OUTPUT)/%.bpf.o: src/ebpf/%.bpf.c $(LIBBPF_OBJ) $(wildcard src/ebpf/%.h) $(VMLINUX) | $(OUTPUT)
	@echo "=== Building BPF code"
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	@echo "=== Building BPF skeletons"
	$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: src/%.c $(wildcard src/%.h) | $(OUTPUT)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build application binary
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) $(LIBLOG_OBJ) | $(OUTPUT)
	$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY: