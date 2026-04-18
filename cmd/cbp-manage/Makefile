# Makefile for cbp-manage CLI

BINARY_NAME=cbp-manage
GO=go
GOFLAGS=-ldflags="-s -w"

.PHONY: all build clean test install help

all: build

build: ## Build the CLI binary
	$(GO) build $(GOFLAGS) -o $(BINARY_NAME) .

clean: ## Remove build artifacts
	rm -f $(BINARY_NAME)
	rm -f test_keys.txt

test: build ## Run basic functionality tests
	@echo "Testing keygen..."
	./$(BINARY_NAME) keygen > test_keys.txt
	@echo "✓ Keygen works"
	@echo ""
	@echo "To test list-issuers:"
	@echo "  1. Add the following public key to server/signature.go AuthorizedSigners:"
	@grep "Public Key" -A 1 test_keys.txt | tail -n 1
	@echo "  2. Restart the server"
	@echo "  3. Run: make test-list-issuers"

test-list-issuers: build ## Test list-issuers command (requires server running)
	@if [ ! -f test_keys.txt ]; then \
		echo "Error: Run 'make test' first to generate keys"; \
		exit 1; \
	fi
	@mkdir -p ~/.cbp-test
	@grep "Private Key" -A 1 test_keys.txt | tail -n 1 > ~/.cbp-test/private_key
	@chmod 600 ~/.cbp-test/private_key
	@echo "Testing list-issuers..."
	CBP_PRIVATE_KEY_FILE=~/.cbp-test/private_key \
	CBP_SERVER_URL=http://localhost:2416 \
	./$(BINARY_NAME) list-issuers
	@rm -rf ~/.cbp-test

install: build ## Install the binary to $GOPATH/bin
	$(GO) install .

help: ## Display this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
