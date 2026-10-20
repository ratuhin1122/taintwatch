SHELL := sh

GO ?= go
VERSION ?= dev
BINARY := build/taintwatch

.PHONY: build test lint fuzz clean

build:
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) ./cmd/taintwatch

test:
	$(GO) test -race ./...

lint:
	$(GO) vet ./...
	@files=$$(gofmt -l cmd internal) || exit $$?; if [ -n "$$files" ]; then printf 'Run gofmt on:\n%s\n' "$$files"; exit 1; fi

fuzz:
	$(GO) test ./cmd/taintwatch -run='^$$' -fuzz=FuzzDispatcher -fuzztime=5s
	$(GO) test ./internal/hookio -run='^$$' -fuzz=FuzzDecoder -fuzztime=5s

clean:
	rm -rf build
