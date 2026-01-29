# TorForge Makefile
# Cross-platform build system for TorForge

BINARY_NAME := torforge
VERSION := 1.1.2
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod

# Build flags
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)"
CGO_ENABLED := 1

# Platforms
LINUX_AMD64 := GOOS=linux GOARCH=amd64
LINUX_ARM64 := GOOS=linux GOARCH=arm64
DARWIN_AMD64 := GOOS=darwin GOARCH=amd64
DARWIN_ARM64 := GOOS=darwin GOARCH=arm64
WINDOWS_AMD64 := GOOS=windows GOARCH=amd64

# Directories
BUILD_DIR := build
CMD_DIR := ./cmd/torforge

.PHONY: all build clean test deps install uninstall linux darwin windows cross help

# Default target
all: deps build

# Build for current platform
build:
	@echo "🔨 Building $(BINARY_NAME) v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "✅ Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Development build with race detector
build-dev:
	@echo "🔨 Building $(BINARY_NAME) (dev mode)..."
	CGO_ENABLED=1 $(GOBUILD) -race $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-dev $(CMD_DIR)

# Install dependencies
deps:
	@echo "📦 Installing dependencies..."
	$(GOMOD) download
	$(GOMOD) verify

# Run tests
test:
	@echo "🧪 Running tests..."
	$(GOTEST) -v -race -cover ./...

# Run tests with coverage report
test-coverage:
	@echo "🧪 Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "📊 Coverage report: coverage.html"

# Integration tests (requires root)
test-integration:
	@echo "🧪 Running integration tests..."
	sudo $(GOTEST) -v -tags=integration ./internal/netfilter/...

# Benchmark tests
bench:
	@echo "⚡ Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

# Clean build artifacts
clean:
	@echo "🧹 Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Install to system
install: build
	@echo "📥 Installing $(BINARY_NAME)..."
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@sudo mkdir -p /etc/torforge
	@if [ ! -f /etc/torforge/torforge.yaml ]; then \
		sudo cp configs/example-config.yaml /etc/torforge/torforge.yaml; \
	fi
	@echo "✅ Installed to /usr/local/bin/$(BINARY_NAME)"

# Uninstall from system
uninstall:
	@echo "🗑️  Uninstalling $(BINARY_NAME)..."
	@sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "✅ Uninstalled"

# Install systemd service
install-service: install
	@echo "📥 Installing systemd service..."
	@sudo cp systemd/torforge.service /etc/systemd/system/
	@sudo systemctl daemon-reload
	@echo "✅ Service installed. Enable with: sudo systemctl enable torforge"

# Cross-compilation targets
linux:
	@echo "🐧 Building for Linux..."
	@mkdir -p $(BUILD_DIR)
	$(LINUX_AMD64) CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)
	$(LINUX_ARM64) CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD_DIR)

darwin:
	@echo "🍎 Building for macOS..."
	@mkdir -p $(BUILD_DIR)
	$(DARWIN_AMD64) CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_DIR)
	$(DARWIN_ARM64) CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_DIR)

windows:
	@echo "🪟 Building for Windows..."
	@mkdir -p $(BUILD_DIR)
	$(WINDOWS_AMD64) CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_DIR)

# Build all platforms
cross: linux darwin windows
	@echo "✅ Cross-compilation complete"
	@ls -la $(BUILD_DIR)/

# Lint code
lint:
	@echo "🔍 Linting..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, skipping"; \
	fi

# Format code
fmt:
	@echo "✨ Formatting code..."
	$(GOCMD) fmt ./...

# Generate mocks (if needed)
generate:
	@echo "⚙️  Generating code..."
	$(GOCMD) generate ./...

# Docker build
docker-build:
	@echo "🐳 Building Docker image..."
	docker build -t torforge:$(VERSION) .

# Docker run (for testing)
docker-run:
	docker run --rm -it --privileged --cap-add=NET_ADMIN torforge:$(VERSION)

# Release (creates tar.gz for each platform)
release: cross
	@echo "📦 Creating release archives..."
	@mkdir -p $(BUILD_DIR)/release
	@cd $(BUILD_DIR) && tar -czf release/$(BINARY_NAME)-$(VERSION)-linux-amd64.tar.gz $(BINARY_NAME)-linux-amd64
	@cd $(BUILD_DIR) && tar -czf release/$(BINARY_NAME)-$(VERSION)-linux-arm64.tar.gz $(BINARY_NAME)-linux-arm64
	@cd $(BUILD_DIR) && tar -czf release/$(BINARY_NAME)-$(VERSION)-darwin-amd64.tar.gz $(BINARY_NAME)-darwin-amd64
	@cd $(BUILD_DIR) && tar -czf release/$(BINARY_NAME)-$(VERSION)-darwin-arm64.tar.gz $(BINARY_NAME)-darwin-arm64
	@cd $(BUILD_DIR) && zip -q release/$(BINARY_NAME)-$(VERSION)-windows-amd64.zip $(BINARY_NAME)-windows-amd64.exe
	@echo "✅ Release archives created in $(BUILD_DIR)/release/"

# Show help
help:
	@echo "TorForge Build System"
	@echo ""
	@echo "Usage:"
	@echo "  make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all            Build for current platform (default)"
	@echo "  build          Build binary"
	@echo "  build-dev      Build with race detector"
	@echo "  deps           Download dependencies"
	@echo "  test           Run unit tests"
	@echo "  test-coverage  Run tests with coverage report"
	@echo "  test-integration Run integration tests (requires root)"
	@echo "  bench          Run benchmarks"
	@echo "  clean          Remove build artifacts"
	@echo "  install        Install to /usr/local/bin"
	@echo "  uninstall      Remove from /usr/local/bin"
	@echo "  install-service Install systemd service"
	@echo "  linux          Cross-compile for Linux"
	@echo "  darwin         Cross-compile for macOS"
	@echo "  windows        Cross-compile for Windows"
	@echo "  cross          Cross-compile for all platforms"
	@echo "  docker-build   Build Docker image"
	@echo "  release        Create release archives"
	@echo "  lint           Run linter"
	@echo "  fmt            Format code"
	@echo "  help           Show this help"
