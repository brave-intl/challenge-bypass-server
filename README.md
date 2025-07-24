# Blinded Tokens Microservice

This is a fork of the [Challenge Bypass Server](https://github.com/privacypass/challenge-bypass-server), that implements the HTTP REST interface, persistence in Postgresql, multiple issuers, etc.

It also uses [cgo bindings to a rust library to implement the cryptographic protocol](https://github.com/brave-intl/challenge-bypass-ristretto-ffi).

## Dependencies

Install Docker.

## Run/build using docker

```
docker-compose up
```

## Linting

This project uses [golangci-lint](https://golangci-lint.run/) for linting, this is run by CI and should be run before raising a PR.

To run locally use `make lint` which runs linting using docker however if you want to run it locally using a binary release (which can be faster) follow the [installation instructions for your platform](https://golangci-lint.run/usage/install/) and then run `golangci-lint run -v ./...`

## Testing

### Unit Tests

Run the below command in order to test changes, if you have an M1 / M2 Mac (or ARM based processor) follow the steps below to setup docker to be able to run the tests
```
make docker-test
```

### Integration Tests

The project includes comprehensive integration tests that verify the entire system working together with all dependencies.

#### What the Integration Tests Do

The integration tests:
- Spin up a complete environment with PostgreSQL, Kafka, Zookeeper, LocalStack (for DynamoDB), and the application
- Test end-to-end flows including:
  - Token redemption flows through Kafka
  - Token signing flows through Kafka
  - Database persistence and retrieval
  - DynamoDB operations
- Verify the application correctly processes messages between Kafka topics
- Ensure proper communication between all services

#### Running Integration Tests

To run the integration tests, simply use:

```bash
make integration-test
# or
make docker-integration-test
```

This command will:
1. Clean up any existing test containers
2. Build all required services
3. Start the test environment (PostgreSQL, Kafka, Zookeeper, LocalStack)
4. Wait for all services to be healthy and ready (~30 seconds)
5. Build and run the test suite
6. Automatically clean up all containers and volumes after completion

#### Manual Cleanup

If the tests are interrupted or you need to manually clean up the test environment:

```bash
make integration-test-clean
```

This will remove all test containers, networks, and volumes created by the integration tests.

#### Viewing Logs

To debug issues or view what's happening during the tests:

```bash
make integration-test-logs
```

This will tail the logs from all services in the integration test environment.

#### Test Configuration

The integration tests use a separate `docker-compose.integration.yml` file which:
- Creates isolated test topics in Kafka
- Uses a dedicated test database
- Runs LocalStack for DynamoDB emulation
- Configures all services with test-specific settings

The test runner writes results to the `./test-results` directory for inspection after test runs.

### Have an M1 / M2 (ARM) Mac?

1.) In Docker Desktop, go to: `Settings -> Docker Engine` <br />
 #### Modify file to include
 ```
  "runtimes": {
    "linux": {
      "path": "linux"
    }
  }
 ```
2.) Modify Docker File
#### Replace `rust_builder` with:
```
FROM arm64v8/rust:1.69 as rust_builder
RUN rustup target add aarch64-unknown-linux-musl
RUN apt-get update && apt-get install -y musl-tools:arm64
RUN git clone https://github.com/brave-intl/challenge-bypass-ristretto-ffi /src
WORKDIR /src
RUN git checkout 1.0.1
RUN CARGO_PROFILE_RELEASE_LTO=true cargo rustc --target=aarch64-unknown-linux-musl --release --crate-type staticlib
```

#### Replace `go_builder` with:
```
FROM arm64v8/golang:1.18 as go_builder
RUN apt-get update && apt-get install -y ca-certificates postgresql-client python3-pip
RUN pip install awscli --upgrade
RUN curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s -- -b $(go env GOPATH)/bin latest
RUN mkdir /src
WORKDIR /src
COPY . .
RUN go mod download
COPY --from=rust_builder /src/target/aarch64-unknown-linux-musl/release/libchallenge_bypass_ristretto_ffi.a /usr/lib/libchallenge_bypass_ristretto_ffi.a
ENV GOARCH=arm64
RUN go build -ldflags '-linkmode external -extldflags "-static"' -tags 'osusergo netgo static_build' -o challenge-bypass-server main.go
CMD ["/src/challenge-bypass-server"]
```

## Deployment

For testing purposes this repo can be deployed to Heroku. The settings set in environment variables `DBCONFIG` and `DATABASE_URL` override other options.
