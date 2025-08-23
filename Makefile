# Integration test configuration
INTEGRATION_COMPOSE_FILE := docker-compose.integration.yml
INTEGRATION_COMPOSE := docker compose -f $(INTEGRATION_COMPOSE_FILE)

docker-psql:
	docker compose exec postgres psql -U btokens

docker-dev:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -p 2416:2416 challenge-bypass /bin/bash

docker-test:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -p 2416:2416 challenge-bypass bash -c \
	"export AWS_PAGER='' && (aws dynamodb delete-table \
	--table-name redemptions --endpoint-url http://dynamodb:8000 --region us-west-2  || \
	aws dynamodb create-table \
	--attribute-definitions AttributeName=id,AttributeType=S \
	--key-schema AttributeName=id,KeyType=HASH \
	--billing-mode PAY_PER_REQUEST \
	--table-name redemptions --endpoint-url http://dynamodb:8000 --region us-west-2 ) \
	&& go test -v -tags='!integration' ./..."

docker-lint:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -p 2416:2416 challenge-bypass golangci-lint run

docker-build:
	docker build -t brave/challenge-bypass:$$(git rev-parse --short HEAD) .
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
	@$(INTEGRATION_COMPOSE) --profile test run --rm test-runner || (echo "❌ Tests failed!"; $(MAKE) integration-test-clean; exit 1)
	
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
