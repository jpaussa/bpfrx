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
