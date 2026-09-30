# Integration test configuration
INTEGRATION_COMPOSE_FILE := docker-compose.integration.yml
INTEGRATION_COMPOSE := docker compose -f $(INTEGRATION_COMPOSE_FILE)

docker-psql:
	docker compose exec postgres psql -U btokens

docker-dev:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -p 2416:2416 challenge-bypass /bin/sh

# The db-tagged suite recreates the dynamodb "redemptions" table itself (see
# utils/test/dynamodb.go), so no aws CLI is needed here.
docker-test:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -p 2416:2416 challenge-bypass \
	go test -v -tags=db ./...

# Ad-hoc aws CLI against the compose services. The dynamodb endpoint is preset
# by the aws-cli service, so only the command itself is needed, e.g.
#   make docker-aws AWS_ARGS="dynamodb list-tables"
docker-aws:
	docker compose --profile tools run --rm aws-cli $(AWS_ARGS)

.PHONY: docker-lint
docker-lint: lint

docker-build:
	docker build \
	--build-arg VERSION=$$(git describe --tags --always --dirty) \
	--build-arg COMMIT=$$(git rev-parse --short HEAD) \
	--build-arg BUILD_TIME=$$(date -u +%Y-%m-%dT%H:%M:%SZ) \
	-t brave/challenge-bypass:$$(git rev-parse --short HEAD) .
	docker tag brave/challenge-bypass:$$(git rev-parse --short HEAD) brave/challenge-bypass:latest

docker-release:
	docker push brave/challenge-bypass:$$(git rev-parse --short HEAD)
	docker push brave/challenge-bypass:latest

generate-avro:
	rm ./avro/generated/*
	gogen-avro --containers=true --package=generated ./avro/generated ./avro/schemas/*
	sed -i 's/Public_key/Issuer_public_key/g' ./avro/generated/signing_result*.go
	sed -i 's/"public_key/"issuer_public_key/g' ./avro/generated/signing_result*.go

lint:
	docker run --rm -v "$$(pwd):/app" --workdir /app golangci/golangci-lint:v2.1.6 golangci-lint run -v ./...

# Integration test commands
.PHONY: integration-test
integration-test: integration-test-clean
	@echo "🏗️  Building services..."
	@$(INTEGRATION_COMPOSE) build
	
	@echo "🚀 Starting services..."
	@$(INTEGRATION_COMPOSE) up -d
	
	@echo "⏳ Waiting for services to be ready..."
	@for i in $$(seq 1 10); do \
		echo -n "$$i... "; \
		sleep 1; \
	done; \
	echo ""
	
	@echo "🏗️  Building test runner..."
	@$(INTEGRATION_COMPOSE) --profile test build test-runner
	
	@echo "🧪 Running integration tests..."
	@TEST_NAME="$${TEST_NAME:-}" && \
	if [ -n "$$TEST_NAME" ]; then \
		echo "Running specific test: $$TEST_NAME"; \
		$(INTEGRATION_COMPOSE) --profile test run --rm test-runner go test -v -tags=integration ./... -run=$$TEST_NAME || (echo "❌ Tests failed!"; $(MAKE) integration-test-clean; exit 1); \
	else \
		echo "Running all tests"; \
		$(INTEGRATION_COMPOSE) --profile test run --rm test-runner || (echo "❌ Tests failed!"; $(MAKE) integration-test-clean; exit 1); \
	fi
	
	@echo "🧹 Cleaning up..."
	@$(MAKE) integration-test-clean
	
	@echo "✅ Integration tests completed successfully!"

.PHONY: integration-test-clean
integration-test-clean:
	@echo "🧹 Cleaning up containers and volumes..."
	@$(INTEGRATION_COMPOSE) --profile test down -v --remove-orphans 2>/dev/null || true

.PHONY: integration-test-logs
integration-test-logs:
	@$(INTEGRATION_COMPOSE) logs -f

# Alias for consistency with existing naming convention
.PHONY: docker-integration-test
docker-integration-test: integration-test
