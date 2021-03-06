.PHONY: all

CLANG ?= clang

LIB_HEADERS := /usr/include/
LIBBPF_HEADERS := /usr/local/include/bpf/
LIBBPF_OBJ := /usr/local/lib64/libbpf.a

MAIN := ./bin/vrft
VRCTL := ./bin/vrctl
GO_SRC := ./cmd/vrft
BPF_SRCS := bpf/vrft_kprobe.bpf.c
BPF_OBJS := bpf/vrft_kprobe.bpf.o

VR_SANDESH := vrouter/sandesh/vr.sandesh

ARCH := $(shell uname -m | sed 's/x86_64/x86/')
CFLAGS := \
  -g \
  -O3 \
  -Wextra \
  -target bpf \
  -fpie \
  -I compat \
  -I compat/uapi/ \
	-I tf-vrouter/include \
	-I tf-common/ \
	-I tf-common/sandesh/library/c \
	-I gen-c \
  -D__TARGET_ARCH_$(ARCH)

all: $(VR_SANDESH) $(BPF_OBJS) vrft vrctl

vr.thrift:
	./tools/thrift -r --out .  --gen go hack/vr.thrift

$(VR_SANDESH):
	./tools/sandesh -o . --gen c tf-vrouter/sandesh/vr.sandesh 

$(BPF_OBJS): $(BPF_SRCS)
	$(CLANG) $(CFLAGS) -c $^

go_env := CC=clang CGO_CFLAGS="-I $(LIBBPF_HEADERS) -I$(LIB_HEADERS) -I compat -I compat/uapi" CGO_LDFLAGS="$(LIBBPF_OBJ)"
vrft:
	$(go_env) go build -v -o $(MAIN) ./cmd/vrft

vrctl:
	go build -o $(VRCTL) ./cmd/vrctl

clean:
	@rm -f $(BPF_OBJS) $(BPF_HEADERS)
	@rm -f $(TARGET)
	@rm -rf gen-c/
