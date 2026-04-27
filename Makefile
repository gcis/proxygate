VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BINARY = proxygate
LDFLAGS = -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build run clean test coverage lint install

build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/proxygate/

run: build
	./bin/$(BINARY)

clean:
	rm -rf bin/ coverage.out coverage.html

test:
	go test -race -v ./...

coverage:
	go test -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	go tool cover -func=coverage.out | tail -1

lint:
	go vet ./...

install: build
	cp bin/$(BINARY) /usr/local/bin/

.DEFAULT_GOAL := build
