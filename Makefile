.PHONY: build test vet clean run release release-check release-tag release-build

BINARY    := bw-secrets
BUILD_DIR := bin
DIST_DIR  := dist
VERSION   ?= dev
LDFLAGS   := -s -w -X github.com/nathabonfim59/bw-secrets/internal/cli.version=$(VERSION)

build:
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/bw-secrets

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

release-build:
	goreleaser build --snapshot --clean
