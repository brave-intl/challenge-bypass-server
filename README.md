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
- Spin up a complete environment with PostgreSQL, Kafka (KRaft mode), LocalStack (for DynamoDB), and the application
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
# run all integration tests
make integration-test
# or run a specific integration test
make integration-test TEST_NAME=TestTokenIssuanceViaKafkaAndRedeemViaHTTPFlow
```

This command will:
1. Clean up any existing test containers
2. Build all required services
3. Start the test environment (PostgreSQL, Kafka, LocalStack)
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

## Issuer admin API and cbp-manage

Operators manage issuers with the `cbp-manage` terminal UI. It talks to the
`/v1/admin` API, which accepts only ed25519-signed requests from an
allowlist of operator keys. This is the same model as the subscriptions
support API. Issuers are never deleted. They are retired in favor of a
replacement.

Rollout, rollback and break-glass procedures:
[`docs/issuer-admin-rollout.md`](docs/issuer-admin-rollout.md).

### Operator setup

1. Generate a key:
   `ssh-keygen -t ed25519 -N "" -C you@brave.com -f ~/.config/cbp-manage/id_ed25519`.
2. Add the `.pub` line to `prodAdminKeys` (production) or `devAdminKeys`
   (staging and dev) in `server/admin_keys.go`, via a PR. The comment must
   be your email; it is written to the audit log. It takes effect on
   deploy.
3. Check access: `cbp-manage --whoami` prints the email your key maps to.
4. Run it:
   `CBP_ADMIN_URL=https://… CBP_ADMIN_PRIVATE_KEY=~/.config/cbp-manage/id_ed25519 go run ./cmd/cbp-manage`.
   The binary builds without cgo: `CGO_ENABLED=0 go build ./cmd/cbp-manage`.

### Retirement rules (enforced by the server)

A retirement names a replacement issuer, a stop-issuing time and a
stop-redeeming time. After stop-issuing, sign requests for the issuer are
**rejected** (HTTP 400, Kafka `issuerInvalid`), never routed to the
replacement. Switch client configuration to the replacement first.
Redemption continues until stop-redeeming.

1. The issuer must be active: not already retiring, retired or expired.
2. The replacement must be a different, active issuer. Its version may
   differ.
3. `stop_issuing_at` must not be in the past (up to 60 seconds of clock
   skew is tolerated).
4. `stop_redeeming_at` must be at least 90 days after `stop_issuing_at`.
5. For v3 issuers, `stop_redeeming_at` must also cover the last key window
   the rotation cron can still create:
   `stop_issuing_at + (buffer + overlap) × duration`.
6. The replacement must not expire before `stop_redeeming_at`.
7. The replacement must already be valid at `stop_issuing_at`.
8. Chain rule: an issuer that replaced another cannot stop issuing before
   that other issuer stops redeeming.
9. The issuer and replacement names must not be prefixes of one another.
   Kafka resolves issuers by prefix, so `X` would silently route to
   `X-next`. Admin create rejects such names for the same reason.

To undo: **cancel** works while the issuer is still retiring. **Postpone**
(a later stop-issuing time) works even after the issuer has retired. Both
leave redemption the same or longer, never shorter.

v1/v2 keys are not rotated by hand. HTTP redemption only checks the newest
v1/v2 key, so rotate by creating a replacement issuer and retiring the old
one.

### Endpoints (all under `/v1/admin`, signed)

| Method | Path | Purpose |
|---|---|---|
| GET | `/whoami` | operator email for the signing key |
| GET | `/issuers` | list with derived status |
| POST | `/issuers` | create (v1/v2/v3) |
| GET | `/issuers/{id}` | detail: keys (public only), retirement chain |
| PATCH | `/issuers/{id}` | `max_tokens`, or a later `expires_at` |
| POST | `/issuers/{id}/retire` | retire in favor of a replacement |
| DELETE | `/issuers/{id}/retire` | cancel a retirement that hasn't started |
| POST | `/issuers/{id}/retire/postpone` | move stop-issuing later |
| GET | `/audit?issuer_id=&limit=` | audit log, newest first |

## Deployment

For testing purposes this repo can be deployed to Heroku. The settings set in environment variables `DBCONFIG` and `DATABASE_URL` override other options.
