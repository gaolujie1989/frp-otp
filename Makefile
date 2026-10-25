GO ?= go
VERSION ?= dev
REVISION := $(shell git rev-parse --short HEAD)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS = -s -w -X main.buildVersion=$(VERSION) -X main.buildRev=$(REVISION) -X main.buildDate=$(BUILD_DATE)

.PHONY: build test vet
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/frp-otp .
test:
	$(GO) test -race ./...
vet:
	$(GO) vet ./...
