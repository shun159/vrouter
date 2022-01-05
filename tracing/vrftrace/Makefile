.PHONY: all

CLANG ?= clang

LIB_HEADERS := /usr/include/
LIBBPF_HEADERS := /usr/include/bpf
LIBBPF_OBJ := /usr/lib/$(shell uname -m)-linux-gnu/libbpf.a

TARGET := ./bin/vrft
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
  -I compat \
  -I compat/uapi/ \
  -D__TARGET_ARCH_$(ARCH)

all: $(VR_SANDESH) $(BPF_OBJS) $(TARGET)

gen_vrthrift:
	./tools/thrift -r --gen go hack/vr.thrift

$(VR_SANDESH):
	./tools/sandesh -o . --gen c tf-vrouter/sandesh/vr.sandesh 

$(BPF_OBJS): $(BPF_SRCS)
	$(CLANG) $(CFLAGS) -c $^

go_env := CC=clang CGO_CFLAGS="-I $(LIBBPF_HEADERS) -I$(LIB_HEADERS) -I compat -I compat/uapi" CGO_LDFLAGS="$(LIBBPF_OBJ)"
$(TARGET):
	$(go_env) go build -o $(TARGET) $(GO_SRC)

clean:
	@rm -f $(BPF_OBJS) $(BPF_HEADERS)
	@rm -f $(TARGET)
	@rm -rf gen-c/
