# WarpShift-TUI build and release automation.
# Usage:
#   make build              Build for the current OS/arch
#   make build-all          Cross-compile for linux, darwin, windows (amd64 + arm64)
#   make test               Run Go tests with race detection
#   make vet                Run Go vet
#   make lint               Run golangci-lint (requires local install)
#   make release            Build all binaries with release version
#   make docker             Build Docker image
#   make clean              Remove build artifacts
#
# Variables (override with env or argument):
#   VERSION     Release version; defaults to "dev"
#   LDFLAGS     Extra linker flags
#   DOCKER_TAG  Docker image tag; defaults to warpshift-tui:local

# ---- Metadata ----
MODULE    := github.com/RecursiveDev/WarpShift-TUI
VERSION   ?= dev
DOCKER_TAG ?= warpshift-tui:local
BUILD_DIR := build
DIST_DIR  := dist

# ---- Linker flags ----
LDFLAGS_BASE := -s -w -X main.version=$(VERSION)
LDFLAGS      := -ldflags="$(LDFLAGS_BASE) $(LDFLAGS)"

# ---- Go commands ----
GO        := go
HOST_GOOS := $(shell $(GO) env GOOS)
GO_BUILD  := $(GO) build -trimpath $(LDFLAGS)
GO_TEST   := $(GO) test -race -count=1
# ---- Targets ----

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build binary for current OS/arch
	@mkdir -p $(BUILD_DIR)
	$(GO_BUILD) -o $(BUILD_DIR)/warpshift$(if $(filter windows,$(HOST_GOOS)),.exe) ./cmd/warpshift

.PHONY: build-all
build-all: ## Cross-compile for linux, darwin, windows (amd64 + arm64)
	@mkdir -p $(DIST_DIR)
	@echo "=== linux/amd64 ==="
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 $(GO_BUILD) -o $(DIST_DIR)/warpshift-linux-amd64   ./cmd/warpshift
	@echo "=== linux/arm64 ==="
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 $(GO_BUILD) -o $(DIST_DIR)/warpshift-linux-arm64   ./cmd/warpshift
	@echo "=== darwin/amd64 ==="
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 $(GO_BUILD) -o $(DIST_DIR)/warpshift-darwin-amd64  ./cmd/warpshift
	@echo "=== darwin/arm64 ==="
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 $(GO_BUILD) -o $(DIST_DIR)/warpshift-darwin-arm64  ./cmd/warpshift
	@echo "=== windows/amd64 ==="
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO_BUILD) -o $(DIST_DIR)/warpshift-windows-amd64.exe ./cmd/warpshift
	@echo ""
	@echo "=== Built artifacts ==="
	@ls -lh $(DIST_DIR)

.PHONY: test
test: ## Run Go tests with race detection
	$(GO_TEST) ./...

.PHONY: vet
vet: ## Run Go vet
	$(GO) vet ./...

.PHONY: cover
cover: ## Run tests and open coverage report
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -html=coverage.out

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run ./...

.PHONY: release
release: clean build-all ## Build release binaries
	@echo "=== Release $(VERSION) built in $(DIST_DIR) ==="
	@ls -lh $(DIST_DIR)

.PHONY: docker
docker: ## Build Docker image
	docker build --build-arg VERSION=$(VERSION) -t $(DOCKER_TAG) .

.PHONY: docker-compose-up
docker-compose-up: ## Start with docker compose
	docker compose up --build

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR) $(DIST_DIR) coverage.out coverage.html
