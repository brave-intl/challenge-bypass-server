docker-psql:
	docker-compose exec postgres psql -U btokens

docker-dev:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -p 2416:2416 challenge-bypass /bin/bash

docker-test:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -p 2416:2416 challenge-bypass bash -c \
	"(aws dynamodb delete-table \
	--table-name redemptions --endpoint-url http://dynamodb:8000 --region us-west-2  || \
	aws dynamodb create-table \
	--attribute-definitions AttributeName=id,AttributeType=S \
	--key-schema AttributeName=id,KeyType=HASH \
	--billing-mode PAY_PER_REQUEST \
	--table-name redemptions --endpoint-url http://dynamodb:8000 --region us-west-2 ) \
	&& go test -v ./..."

docker-lint:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -p 2416:2416 challenge-bypass golangci-lint run

docker:
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
	docker run --rm -v "$$(pwd):/app" --workdir /app golangci/golangci-lint:v1.49.0 golangci-lint run -v ./...
