.PHONY: build test vet clean run release release-check release-tag release-build

BINARY    := bw-secrets
BUILD_DIR := bin
DIST_DIR  := dist
LDFLAGS   := -s -w
VERSION   ?= dev

build:
	go build -ldflags "$(LDFLAGS) -X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY) ./cmd/bw-secrets

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf $(BUILD_DIR) $(DIST_DIR)

run: build
	./$(BUILD_DIR)/$(BINARY)

release: release-check release-tag release-build
	@echo "Release $(VERSION) complete — binaries in $(DIST_DIR)/"

release-check:
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo "error: working tree is dirty, commit or stash changes first"; \
		exit 1; \
	fi
	@if [ "$(VERSION)" = "dev" ]; then \
		echo "error: VERSION is required (make release VERSION=v1.0.0)"; \
		exit 1; \
	fi
	@if git rev-parse "$(VERSION)" >/dev/null 2>&1; then \
		echo "error: tag $(VERSION) already exists"; \
		exit 1; \
	fi

release-tag:
	git tag -a "$(VERSION)" -m "Release $(VERSION)"
	@echo "Created tag $(VERSION) (not pushed)"

release-build: build
	@mkdir -p $(DIST_DIR)
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS) -X main.version=$(VERSION)" -o $(DIST_DIR)/$(BINARY)_$(VERSION)_linux_amd64       ./cmd/bw-secrets
	GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS) -X main.version=$(VERSION)" -o $(DIST_DIR)/$(BINARY)_$(VERSION)_linux_arm64       ./cmd/bw-secrets
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS) -X main.version=$(VERSION)" -o $(DIST_DIR)/$(BINARY)_$(VERSION)_linux_amd64_musl  ./cmd/bw-secrets
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS) -X main.version=$(VERSION)" -o $(DIST_DIR)/$(BINARY)_$(VERSION)_darwin_amd64      ./cmd/bw-secrets
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS) -X main.version=$(VERSION)" -o $(DIST_DIR)/$(BINARY)_$(VERSION)_darwin_arm64      ./cmd/bw-secrets
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS) -X main.version=$(VERSION)" -o $(DIST_DIR)/$(BINARY)_$(VERSION)_windows_amd64.exe ./cmd/bw-secrets
	GOOS=windows GOARCH=arm64 go build -ldflags "$(LDFLAGS) -X main.version=$(VERSION)" -o $(DIST_DIR)/$(BINARY)_$(VERSION)_windows_arm64.exe ./cmd/bw-secrets
	@ls -lh $(DIST_DIR)/
