CLANG ?= clang
GO ?= go
BINARY := bpfrxd
PREFIX ?= /usr/local

# eBPF compilation flags
BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf

.PHONY: all generate build install clean test

all: generate build

# Generate Go bindings from eBPF C programs via bpf2go
generate:
	$(GO) generate ./pkg/dataplane/...

# Build the daemon binary
build:
	CGO_ENABLED=0 $(GO) build -o $(BINARY) ./cmd/bpfrxd

install: build
	install -m 0755 $(BINARY) $(PREFIX)/sbin/$(BINARY)

test:
	$(GO) test ./...

clean:
	rm -f $(BINARY)
	rm -f pkg/dataplane/*_bpfel.go pkg/dataplane/*_bpfeb.go
	rm -f pkg/dataplane/*_bpfel.o pkg/dataplane/*_bpfeb.o

# Test environment management (Incus VM/container)
.PHONY: test-env-init test-vm test-ct test-deploy test-ssh test-destroy test-status

test-env-init:
	./test/incus/setup.sh init

test-vm:
	./test/incus/setup.sh create-vm

test-ct:
	./test/incus/setup.sh create-ct

test-deploy: build
	./test/incus/setup.sh deploy

test-ssh:
	./test/incus/setup.sh ssh

test-destroy:
	./test/incus/setup.sh destroy

test-status:
	./test/incus/setup.sh status
