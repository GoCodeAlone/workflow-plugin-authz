.PHONY: build test install clean cross-build

BINARY_NAME = workflow-plugin-authz
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS = -ldflags "-X github.com/GoCodeAlone/workflow-plugin-authz/internal.Version=$(VERSION)"
INSTALL_DIR ?= data/plugins/$(BINARY_NAME)
INSTALL_PATH = $(if $(DESTDIR),$(DESTDIR)/$(INSTALL_DIR),$(INSTALL_DIR))
GO_ENV = GOWORK=off GOPRIVATE=github.com/GoCodeAlone/*
PLATFORMS = linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

build:
	$(GO_ENV) go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/$(BINARY_NAME)

test:
	$(GO_ENV) go test ./... -v -race

install: build
	mkdir -p $(INSTALL_PATH)
	cp bin/$(BINARY_NAME) $(INSTALL_PATH)/
	cp plugin.json $(INSTALL_PATH)/
	cp plugin.contracts.json $(INSTALL_PATH)/

cross-build:
	@mkdir -p bin
	@for platform in $(PLATFORMS); do \
		os=$${platform%%/*}; \
		arch=$${platform##*/}; \
		output=bin/$(BINARY_NAME)-$${os}-$${arch}; \
		echo "Building $${output}..."; \
		GOOS=$${os} GOARCH=$${arch} $(GO_ENV) \
			go build $(LDFLAGS) -o $${output} ./cmd/$(BINARY_NAME); \
	done

clean:
	rm -rf bin/
