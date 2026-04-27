VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BINARY = proxygate
LDFLAGS = -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build run clean test lint

build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/proxygate/

run: build
	./bin/$(BINARY)

clean:
	rm -rf bin/

test:
	go test -race -v ./...

lint:
	go vet ./...

install: build
	cp bin/$(BINARY) /usr/local/bin/

.DEFAULT_GOAL := build
