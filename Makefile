COVERAGE_FILE ?= coverage.out

.PHONY: help
help: ## Show this help message
	@echo "airunner - Go-based microservices architecture"
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ { printf "  %-20s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: release-snapshot
release-snapshot: ## Release a snapshot version
	goreleaser build --clean --snapshot --single-target

.PHONY: build
build: build-cli build-server ## Build all binaries

.PHONY: build-cli
build-cli: ## Build CLI binary (multi-purpose client)
	@mkdir -p bin
	go build -o bin/airunner-cli ./cmd/cli

.PHONY: build-server
build-server: ## Build server binary (job queue server)
	@mkdir -p bin
	go build -o bin/airunner-server ./cmd/server

.PHONY: proto-install
proto-install: ## Install protoc-gen-go and protoc-gen-connect-go
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install connectrpc.com/connect/cmd/protoc-gen-connect-go@latest
	go install github.com/bufbuild/buf/cmd/buf@latest

.PHONY: proto-generate
proto-generate: ## Generate Go code from proto files
	cd api && bunx @bufbuild/buf generate

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

.PHONY: dynamodb
dynamodb: ## Start local DynamoDB
	docker compose -f .buildkite/docker-compose.yml up dynamodb --wait -d

.PHONY: localstack
localstack: ## Start LocalStack (SQS)
	docker compose -f .buildkite/docker-compose.yml up localstack --wait -d

.PHONY: infra-up
infra-up: ## Start all local infrastructure (DynamoDB + LocalStack)
	docker compose -f .buildkite/docker-compose.yml up dynamodb localstack --wait -d

.PHONY: infra-down
infra-down: ## Stop all local infrastructure
	docker compose -f .buildkite/docker-compose.yml down

.PHONY: test
test: ## Run tests with coverage
	go test -coverprofile $(COVERAGE_FILE) -covermode atomic -v ./...

.PHONY: test-integration
test-integration: ## Run all integration tests (uses testcontainers, no infra needed)
	go test -tags integration -v ./...

.PHONY: test-integration-postgres
test-integration-postgres: ## Run PostgreSQL integration tests only (via testcontainers)
	go test -tags integration -v ./internal/store/postgres/

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

.PHONY: terraform-init
terraform-init: ## Initialize Terraform
	cd infra && terraform init

.PHONY: terraform-apply
terraform-apply: ## Apply Terraform configuration
	cd infra && terraform apply -var-file=terraform.tfvars

.PHONY: terraform-plan
terraform-plan: ## Plan Terraform configuration
	cd infra && terraform plan -var-file=terraform.tfvars

.PHONY: terraform-validate
terraform-validate: ## Validate Terraform configuration
	cd infra && terraform validate

.PHONY: terraform-fmt
terraform-fmt: ## Check Terraform formatting
	cd infra && terraform fmt -check -diff

.PHONY: terraform-verify
terraform-verify: terraform-validate terraform-fmt terraform-plan ## Run all Terraform verification checks
