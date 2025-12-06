COVERAGE_FILE ?= coverage.out

.PHONY: help
help: ## Show this help message
	@echo "airunner - Go-based microservices architecture"
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ { printf "  %-20s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build all binaries
	@mkdir -p bin
	go build -o bin/airunner-cli ./cmd/cli
	go build -o bin/airunner-server ./cmd/server

.PHONY: build-cli
build-cli: ## Build CLI binary (multi-purpose client)
	@mkdir -p bin
	go build -o bin/airunner-cli ./cmd/cli

.PHONY: build-server
build-server: ## Build server binary (job queue server)
	@mkdir -p bin
	go build -o bin/airunner-server ./cmd/server

.PHONY: proto-generate
proto-generate: ## Generate Go code from proto files
	cd api && buf generate

.PHONY: proto-lint
proto-lint: ## Lint protocol buffer files
	cd api && buf lint

.PHONY: proto-breaking
proto-breaking: ## Check for breaking changes in proto files
	cd api && buf breaking

.PHONY: certs
certs: ## Generate local TLS certificates
	@mkdir -p .certs
	@mkcert -cert-file .certs/cert.pem -key-file .certs/key.pem localhost 127.0.0.1 ::1

.PHONY: test
test: ## Run tests with coverage
	go test -coverprofile $(COVERAGE_FILE) -covermode atomic -v ./...

.PHONY: test-coverage
test-coverage: test ## Run tests and show coverage report
	go tool cover -html=$(COVERAGE_FILE)

.PHONY: lint
lint: ## Run linter
	golangci-lint run ./...

.PHONY: lint-fix
lint-fix: ## Run linter with auto-fix
	golangci-lint run --fix ./...

.PHONY: clean
clean: ## Clean build artifacts
	rm -rf bin/
	rm -f $(COVERAGE_FILE)

.PHONY: snapshot
snapshot: ## Build and release a snapshot version
	goreleaser release --clean --snapshot
