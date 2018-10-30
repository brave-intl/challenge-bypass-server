docker-migrate-up:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm challenge-bypass ./bin/migrate-up.sh

docker-migrate-down:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm challenge-bypass ./bin/migrate-down.sh $(migration)

docker-psql:
	docker-compose exec postgres psql -U btokens

docker-dev:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -p 2416:2416 challenge-bypass /bin/bash

docker-test:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -p 2416:2416 challenge-bypass go test ./...
