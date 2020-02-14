docker-psql:
	docker-compose exec postgres psql -U btokens

docker-dev:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -p 2416:2416 challenge-bypass /bin/bash

docker-test:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -p 2416:2416 challenge-bypass go test ./...

docker-test1:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -p 2416:2416 challenge-bypass bash -c "aws dynamodb create-table \
	--attribute-definitions AttributeName=issuerId,AttributeType=S AttributeName=id,AttributeType=S \
	--key-schema AttributeName=issuerId,KeyType=HASH AttributeName=id,KeyType=RANGE \
	--billing-mode PAY_PER_REQUEST \
	--table-name redemptions --endpoint-url http://dynamodb:8000 --region us-east-1" \
	&& go test ./...

docker-lint:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -p 2416:2416 challenge-bypass golangci-lint run

docker:
	docker build -t brave/challenge-bypass:$$(git rev-parse --short HEAD) .
	docker tag brave/challenge-bypass:$$(git rev-parse --short HEAD) brave/challenge-bypass:latest

docker-release:
	docker push brave/challenge-bypass:$$(git rev-parse --short HEAD)
	docker push brave/challenge-bypass:latest
