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
	$(GO) test ./internal/replay -run='^$$' -fuzz=FuzzCompare -fuzztime=5s
	$(GO) test ./internal/eval -run='^$$' -fuzz=FuzzDecode -fuzztime=5s
	$(GO) test ./internal/detect/pasted -run='^$$' -fuzz=FuzzScan -fuzztime=5s
	$(GO) test ./internal/detect/hidden -run='^$$' -fuzz=FuzzScan -fuzztime=5s
	$(GO) test ./internal/detect/decoderun -run='^$$' -fuzz=FuzzAnalyze -fuzztime=5s
	$(GO) test ./internal/policy -run='^$$' -fuzz=FuzzPolicy -fuzztime=5s
	$(GO) test ./internal/shellparse -run='^$$' -fuzz=FuzzParse -fuzztime=5s
	$(GO) test ./cmd/taintwatch -run='^$$' -fuzz=FuzzDispatcher -fuzztime=5s
	$(GO) test ./internal/hookio -run='^$$' -fuzz=FuzzDecoder -fuzztime=5s
	$(GO) test ./internal/state -run='^$$' -fuzz=FuzzSessionState -fuzztime=5s
	$(GO) test ./internal/state -run='^$$' -fuzz=FuzzSanitizeSessionID -fuzztime=5s
	$(GO) test ./internal/taint -run='^$$' -fuzz=FuzzCommandWords -fuzztime=5s

clean:
	rm -rf build
