SHELL := sh

GO ?= go
VERSION ?= dev
FUZZTIME ?= 5s
FUZZWORKERS ?= 2
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
	$(GO) test ./internal/detect/encoded -run='^$$' -fuzz=FuzzScan -fuzztime=$(FUZZTIME) -parallel=$(FUZZWORKERS)
	$(GO) test ./internal/valuematch -run='^$$' -fuzz=FuzzExtractMatch -fuzztime=$(FUZZTIME) -parallel=$(FUZZWORKERS)
	$(GO) test ./internal/replay -run='^$$' -fuzz=FuzzCompare -fuzztime=$(FUZZTIME) -parallel=$(FUZZWORKERS)
	$(GO) test ./internal/eval -run='^$$' -fuzz=FuzzDecode -fuzztime=$(FUZZTIME) -parallel=$(FUZZWORKERS)
	$(GO) test ./internal/detect/pasted -run='^$$' -fuzz=FuzzScan -fuzztime=$(FUZZTIME) -parallel=$(FUZZWORKERS)
	$(GO) test ./internal/detect/hidden -run='^$$' -fuzz=FuzzScan -fuzztime=$(FUZZTIME) -parallel=$(FUZZWORKERS)
	$(GO) test ./internal/detect/decoderun -run='^$$' -fuzz=FuzzAnalyze -fuzztime=$(FUZZTIME) -parallel=$(FUZZWORKERS)
	$(GO) test ./internal/policy -run='^$$' -fuzz=FuzzPolicy -fuzztime=$(FUZZTIME) -parallel=$(FUZZWORKERS)
	$(GO) test ./internal/shellparse -run='^$$' -fuzz=FuzzParse -fuzztime=$(FUZZTIME) -parallel=$(FUZZWORKERS)
	$(GO) test ./cmd/taintwatch -run='^$$' -fuzz=FuzzDispatcher -fuzztime=$(FUZZTIME) -parallel=$(FUZZWORKERS)
	$(GO) test ./internal/hookio -run='^$$' -fuzz=FuzzDecoder -fuzztime=$(FUZZTIME) -parallel=$(FUZZWORKERS)
	$(GO) test ./internal/state -run='^$$' -fuzz=FuzzSessionState -fuzztime=$(FUZZTIME) -parallel=$(FUZZWORKERS)
	$(GO) test ./internal/state -run='^$$' -fuzz=FuzzSanitizeSessionID -fuzztime=$(FUZZTIME) -parallel=$(FUZZWORKERS)
	$(GO) test ./internal/taint -run='^$$' -fuzz=FuzzCommandWords -fuzztime=$(FUZZTIME) -parallel=$(FUZZWORKERS)

clean:
	rm -rf build
