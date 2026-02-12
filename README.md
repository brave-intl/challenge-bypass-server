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
# run all integration tests
make integration-test
# or run a specific integration test
make integration-test TEST_NAME=TestTokenIssuanceViaKafkaAndRedeemViaHTTPFlow
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

## Management API

The server provides a REST API for managing issuers. This API is secured using Ed25519 signature verification to ensure only authorized administrators can access it.

### Authentication Protocol Specification

**Protocol:** Ed25519 Signature-Based Request Authentication

**Purpose:** Authenticate and authorize administrative API requests to prevent unauthorized access to issuer management operations.

#### Protocol Overview

Each request to a management endpoint must be cryptographically signed by an authorized Ed25519 private key. The server verifies the signature and checks that the public key is on the authorized signers whitelist before processing the request.

#### Signing Algorithm

1. **Canonical Request Construction:**
   ```
   canonical_request = METHOD + "\n" + PATH + QUERY + "\n" + TIMESTAMP + "\n" + BODY
   ```
   - `METHOD`: HTTP method in uppercase (e.g., "GET", "POST")
   - `PATH`: Request path (e.g., "/api/v1/manage/issuers")
   - `QUERY`: Raw query string including "?" if present (e.g., "?force=true"), empty string if no query
   - `TIMESTAMP`: Unix timestamp in seconds (UTC) as string
   - `BODY`: Raw request body bytes (empty string for GET requests)

2. **Signature Generation:**
   ```
   signature = Ed25519-Sign(private_key, canonical_request)
   ```

3. **Request Headers:**
   - `X-Signature`: Base64(signature)
   - `X-Public-Key`: Base64(public_key_bytes)  // Must be exactly 32 bytes
   - `X-Timestamp`: TIMESTAMP

#### Verification Algorithm

Server performs verification in order from cheapest to most expensive operations:

1. **Header Validation:** Verify all required headers present
2. **Timestamp Validation:**
   - Parse timestamp as Unix seconds
   - Reject if `|now - timestamp| > 5 minutes` (prevents replay attacks)
3. **Public Key Validation:**
   - Decode base64 public key
   - Verify length is exactly 32 bytes
4. **Authorization Check:** Verify public key is in authorized signers allowlist
5. **Signature Verification:**
   - Reconstruct canonical request from incoming request
   - Verify Ed25519 signature using `Ed25519-Verify(public_key, canonical_request, signature)`

#### Threat Model

**Threats Addressed:**
- **Unauthorized Access:** Only holders of authorized private keys can call API
- **Request Tampering:** Signature covers all request components (method, path, query, timestamp, body)
- **Replay Attacks:** 5-minute timestamp window prevents reuse of old signatures
- **Timing Attacks:** Constant-time comparison for signature and authorization checks
- **Denial of Service:** Per-IP rate limiting (60 requests/minute default)

**Known Limitations:**
- No nonce/jti: Requests can be replayed within the 5-minute timestamp window
- Authorized signers configured at server startup (no dynamic key rotation)
- Rate limiter uses in-memory storage (state resets on server restart)

#### Security Properties

- **Algorithm:** Ed25519 (RFC 8032)
- **Signature Size:** 64 bytes
- **Public Key Size:** 32 bytes
- **Timestamp Tolerance:** ±5 minutes
- **Rate Limit:** 60 requests/minute per IP (configurable)
- **Max Request Body:** 1 MiB

### Security & Authentication

All management API endpoints require request signatures using Ed25519 public-key cryptography.

#### Setting Up Authorized Signers

1. **Generate an Ed25519 key pair**:
   ```bash
   # Using OpenSSL
   openssl genpkey -algorithm Ed25519 -out private_key.pem
   openssl pkey -in private_key.pem -pubout -out public_key.pem

   # Extract base64-encoded public key
   openssl pkey -pubin -in public_key.pem -outform DER | tail -c 32 | base64
   ```

2. **Configure authorized signers** in `server/signature.go`:
   ```go
   var AuthorizedSigners = []string{
       "base64-encoded-ed25519-public-key-here",
   }
   ```

#### Request Signature Format

All management API requests must include these headers:

- **X-Signature**: Base64-encoded Ed25519 signature
- **X-Public-Key**: Base64-encoded Ed25519 public key (32 bytes)
- **X-Timestamp**: Unix timestamp in seconds (UTC)

The signature is computed over: `METHOD\nPATH?QUERY\nTIMESTAMP\nBODY`

**Example signing (Python)**:
```python
import ed25519
import base64
import time
import requests

# Load your private key
private_key = ed25519.SigningKey(base64.b64decode("your-private-key-base64"))
public_key = private_key.get_verifying_key()

# Prepare request
method = "GET"
path = "/api/v1/manage/issuers"
timestamp = str(int(time.time()))
body = ""

# Build signing message
message = f"{method}\n{path}\n{timestamp}\n{body}"

# Sign
signature = private_key.sign(message.encode())

# Make request
headers = {
    "X-Signature": base64.b64encode(signature).decode(),
    "X-Public-Key": base64.b64encode(public_key.to_bytes()).decode(),
    "X-Timestamp": timestamp,
}

response = requests.get(f"http://localhost:2416{path}", headers=headers)
```

### API Endpoints

#### List All Issuers

```bash
GET /api/v1/manage/issuers
```

Returns all issuers with their associated keys.

**Rate Limits**: 60 requests per minute per IP address.

**Response Example**:
```json
{
  "issuers": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "brave-rewards",
      "cohort": 1,
      "max_tokens": 40,
      "version": 3,
      "keys": [...]
    }
  ],
  "total": 1
}
```

## Deployment

For testing purposes this repo can be deployed to Heroku. The settings set in environment variables `DBCONFIG` and `DATABASE_URL` override other options.
