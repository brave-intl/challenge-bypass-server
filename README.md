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

The server provides a comprehensive REST API for managing issuers and cryptographic keys. This API is secured using Ed25519 signature verification to ensure only authorized administrators can make changes.

### Security & Authentication

All management API endpoints require request signatures using Ed25519 public-key cryptography. This ensures requests come from authorized administrators and prevents tampering.

#### Setting Up Authorized Signers

1. **Generate an Ed25519 key pair** (if you don't have one):
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
       // Add more authorized public keys as needed
   }
   ```

   > **Security Note**: In production, load these from environment variables or a secure configuration system, not hardcoded values.

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
method = "POST"
path = "/api/v1/manage/issuers"
query = ""
timestamp = str(int(time.time()))
body = '{"name":"example-issuer","cohort":1,"version":3,"duration":"P1D","buffer":2}'

# Build signing message
message = f"{method}\n{path}{query}\n{timestamp}\n{body}"

# Sign
signature = private_key.sign(message.encode())

# Make request
headers = {
    "X-Signature": base64.b64encode(signature).decode(),
    "X-Public-Key": base64.b64encode(public_key.to_bytes()).decode(),
    "X-Timestamp": timestamp,
    "Content-Type": "application/json"
}

response = requests.post(f"http://localhost:2416{path}",
                        data=body,
                        headers=headers)
```

**Example signing (Go)**:
```go
package main

import (
    "crypto/ed25519"
    "encoding/base64"
    "fmt"
    "time"
)

func signRequest(privateKey ed25519.PrivateKey, method, path, query string, body []byte) (string, string, string) {
    timestamp := fmt.Sprintf("%d", time.Now().Unix())
    requestTarget := path
    if query != "" {
        requestTarget = path + "?" + query
    }

    message := fmt.Sprintf("%s\n%s\n%s\n%s", method, requestTarget, timestamp, string(body))
    signature := ed25519.Sign(privateKey, []byte(message))
    publicKey := privateKey.Public().(ed25519.PublicKey)

    return base64.StdEncoding.EncodeToString(signature),
           base64.StdEncoding.EncodeToString(publicKey),
           timestamp
}
```

### Issuer Management

Issuers are the top-level entities that contain cryptographic keys for token signing. The server supports three issuer versions (v1, v2, v3), with v3 being recommended for new deployments.

#### List All Issuers

```bash
GET /api/v1/manage/issuers

# Example response:
{
  "issuers": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "brave-rewards",
      "cohort": 1,
      "max_tokens": 40,
      "version": 3,
      "buffer": 2,
      "overlap": 0,
      "duration": "P1D",
      "valid_from": "2024-01-01T00:00:00Z",
      "expires_at": "2025-01-01T00:00:00Z",
      "created_at": "2024-01-01T00:00:00Z",
      "keys": [...]
    }
  ],
  "total": 1
}
```

#### Get Single Issuer

```bash
GET /api/v1/manage/issuers/{issuer-id}

# Example:
GET /api/v1/manage/issuers/550e8400-e29b-41d4-a716-446655440000
```

#### Create Issuer

```bash
POST /api/v1/manage/issuers

# V3 Issuer (recommended):
{
  "name": "brave-rewards",
  "cohort": 1,
  "max_tokens": 40,
  "version": 3,
  "buffer": 2,
  "overlap": 0,
  "duration": "P1D",
  "valid_from": "2024-01-01T00:00:00Z",
  "expires_at": "2025-01-01T00:00:00Z"
}

# V1/V2 Issuer (legacy):
{
  "name": "legacy-issuer",
  "cohort": 1,
  "max_tokens": 40,
  "version": 1,
  "expires_at": "2025-01-01T00:00:00Z"
}
```

**Field Descriptions:**
- `name`: Unique identifier for the issuer (e.g., "brave-rewards")
- `cohort`: Numeric cohort identifier for key isolation
- `max_tokens`: Maximum tokens per redemption request
- `version`: Issuer version (1, 2, or 3) - defaults to 3
- `buffer`: **(v3 only)** Number of active keys to maintain
- `overlap`: **(v3 only)** Number of overlapping key periods
- `duration`: **(v3 only)** ISO 8601 duration for key validity (e.g., "P1D" = 1 day, "P30D" = 30 days)
- `valid_from`: Start time for issuer validity (UTC)
- `expires_at`: Expiration time for issuer (UTC)

#### Delete Issuer

```bash
DELETE /api/v1/manage/issuers/{issuer-id}

# Force delete (bypasses safety checks):
DELETE /api/v1/manage/issuers/{issuer-id}?force=true
```

**Safety checks** (can be bypassed with `?force=true`):
- Cannot delete issuers with active keys
- Cannot delete issuers that haven't expired yet
- Warns about potential token invalidation

### Key Management

Keys are the cryptographic key pairs used to sign and verify tokens. Each issuer can have multiple keys with time-based validity periods.

#### List Keys for an Issuer

```bash
GET /api/v1/manage/issuers/{issuer-id}/keys

# Include expired keys:
GET /api/v1/manage/issuers/{issuer-id}/keys?include_expired=true

# Example response:
{
  "keys": [
    {
      "id": "660e8400-e29b-41d4-a716-446655440001",
      "public_key": "base64-encoded-public-key",
      "cohort": 1,
      "start_at": "2024-01-01T00:00:00Z",
      "end_at": "2024-01-02T00:00:00Z",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ],
  "total": 1
}
```

#### Get Single Key

```bash
GET /api/v1/manage/issuers/{issuer-id}/keys/{key-id}
```

#### Create Key

```bash
POST /api/v1/manage/issuers/{issuer-id}/keys

# With custom time bounds:
{
  "start_at": "2024-01-01T00:00:00Z",
  "end_at": "2024-01-02T00:00:00Z"
}

# Without time bounds (uses issuer defaults):
{}
```

#### Delete Key

```bash
DELETE /api/v1/manage/issuers/{issuer-id}/keys/{key-id}

# Force delete (bypasses safety checks):
DELETE /api/v1/manage/issuers/{issuer-id}/keys/{key-id}?force=true
```

**Safety check**: Cannot delete active keys (keys that are currently valid) without `?force=true`.

#### Rotate Keys

Key rotation creates new keys and automatically updates the expiration of the currently active key to create a smooth transition period (overlap).

```bash
POST /api/v1/manage/issuers/{issuer-id}/keys/rotate

# Rotate with default 1-month overlap:
{
  "count": 1
}

# Rotate with custom overlap (7 days):
{
  "count": 1,
  "overlap": "P7D"
}

# Create multiple keys:
{
  "count": 3,
  "overlap": "P14D"
}

# Example response:
{
  "created_keys": [
    {
      "id": "770e8400-e29b-41d4-a716-446655440002",
      "public_key": "base64-new-public-key",
      "cohort": 1,
      "start_at": "2024-01-15T10:00:00Z",
      "end_at": "2024-01-16T10:00:00Z",
      "created_at": "2024-01-15T10:00:00Z"
    }
  ],
  "updated_keys": [
    {
      "id": "660e8400-e29b-41d4-a716-446655440001",
      "public_key": "base64-old-public-key",
      "cohort": 1,
      "start_at": "2024-01-14T10:00:00Z",
      "end_at": "2024-01-22T10:00:00Z",
      "created_at": "2024-01-14T10:00:00Z"
    }
  ],
  "message": "Keys rotated successfully"
}
```

**How rotation works:**
1. Creates new key(s) starting from now
2. Updates the currently active key's expiration to: `now + overlap`
3. During the overlap period, both old and new keys are valid
4. Tokens signed with the old key remain valid during the overlap
5. New tokens should use the new key
6. After overlap expires, only the new key is valid

**Overlap duration** (ISO 8601 format):
- `P7D` = 7 days
- `P1M` = 1 month (default)
- `P90D` = 90 days
- `PT2H` = 2 hours

### Key Rotation Workflow

Here's a recommended workflow for rotating keys in production:

```bash
# 1. Check current keys
curl -X GET https://api.example.com/api/v1/manage/issuers/$ISSUER_ID/keys \
  -H "X-Signature: $SIGNATURE" \
  -H "X-Public-Key: $PUBLIC_KEY" \
  -H "X-Timestamp: $TIMESTAMP"

# 2. Rotate with appropriate overlap (e.g., 30 days for monthly rotation)
curl -X POST https://api.example.com/api/v1/manage/issuers/$ISSUER_ID/keys/rotate \
  -H "X-Signature: $SIGNATURE" \
  -H "X-Public-Key: $PUBLIC_KEY" \
  -H "X-Timestamp: $TIMESTAMP" \
  -H "Content-Type: application/json" \
  -d '{"count": 1, "overlap": "P30D"}'

# 3. Verify new key was created and old key was updated
curl -X GET https://api.example.com/api/v1/manage/issuers/$ISSUER_ID/keys \
  -H "X-Signature: $SIGNATURE" \
  -H "X-Public-Key: $PUBLIC_KEY" \
  -H "X-Timestamp: $TIMESTAMP"

# 4. Update your token signing service to use the new key

# 5. After overlap period expires, old tokens will naturally expire
#    No manual cleanup needed
```

### Best Practices

1. **Key Rotation Schedule**
   - Rotate keys regularly (e.g., monthly or quarterly)
   - Use overlap periods longer than your token lifetime
   - Schedule rotations during low-traffic periods

2. **Overlap Periods**
   - Minimum: 2x your longest token lifetime
   - Recommended: 1 month for most use cases
   - Longer for critical systems (90 days)

3. **Security**
   - Keep private keys secure and never commit them to version control
   - Use hardware security modules (HSMs) for production private keys
   - Rotate authorized signer keys periodically
   - Monitor management API access logs

4. **Monitoring**
   - Set up alerts for key expiration (30 days, 7 days, 1 day before)
   - Monitor the `cbp_api_manage_issuer_total` Prometheus metric
   - Track failed signature verifications

5. **Backup & Recovery**
   - Keep secure backups of issuer configurations
   - Document your key rotation procedures
   - Test recovery procedures regularly

6. **Testing**
   - Always test rotations in staging first
   - Verify token redemption works during overlap
   - Check both old and new tokens validate correctly

### Time Zones

All timestamps in the Management API use **UTC** and are formatted as **RFC3339**. Examples:
- `2024-01-15T10:30:00Z`
- `2024-12-31T23:59:59Z`

Always use UTC when creating issuers and keys to avoid timezone-related issues.

### Error Responses

The API returns standard HTTP status codes:

- `200 OK`: Request successful
- `201 Created`: Resource created successfully
- `204 No Content`: Resource deleted successfully
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Missing or invalid signature
- `403 Forbidden`: Public key not authorized
- `404 Not Found`: Resource not found
- `409 Conflict`: Cannot perform operation (e.g., deleting active keys)
- `413 Request Entity Too Large`: Request body > 1 MiB
- `500 Internal Server Error`: Server error

Example error response:
```json
{
  "error": "Cannot delete issuer with 2 active key(s). Active keys can still be used for signing and redemption..."
}
```

### Rate Limiting

The Management API includes built-in rate limiting to prevent abuse and ensure service stability.

#### Default Limits

- **60 requests per minute** per IP address
- **1 minute sliding window**
- Independent rate limits per IP address

#### How It Works

The rate limiter uses a **sliding window algorithm**:
1. Each IP address gets an independent rate limit
2. The system tracks request timestamps for each IP
3. Requests outside the time window are automatically removed
4. When limit is reached, requests return HTTP 429 (Too Many Requests)
5. Old limiters are automatically cleaned up to prevent memory leaks

#### Configuration

Rate limits are currently hardcoded in `server/server.go`. To customize:

```go
// In setupRouter()
managementRateLimiter := NewRateLimiter(
    60,              // requests per minute
    1*time.Minute,   // time window
)
```

For production deployments with multiple instances, consider implementing distributed rate limiting using Redis or a similar shared storage system.

#### Headers

When rate limited, responses include:
- **Status Code**: 429 Too Many Requests
- **Body**: "Rate limit exceeded. Please try again later."

#### Monitoring

Track rate limiting via Prometheus metrics:
- `cbp_api_rate_limit_exceeded_total`: Total number of rate-limited requests

#### Best Practices

1. **Client-side retry logic**: Implement exponential backoff when receiving 429 responses
2. **Request batching**: Batch multiple operations when possible
3. **Caching**: Cache responses on the client side
4. **Monitor limits**: Set up alerts for frequent rate limiting

#### X-Forwarded-For Support

The rate limiter correctly identifies client IPs behind proxies and load balancers:
- Checks `X-Forwarded-For` header (uses first IP in chain)
- Falls back to `X-Real-IP` header
- Falls back to direct connection IP

Ensure your reverse proxy/load balancer sets these headers correctly.

## Deployment

For testing purposes this repo can be deployed to Heroku. The settings set in environment variables `DBCONFIG` and `DATABASE_URL` override other options.
