# Management API Integration Testing

This document describes how the Management API is tested as part of the integration test suite.

## Overview

The Management API integration tests verify:
- Ed25519 signature verification
- Authorization (allowed/denied signers)
- Timestamp validation (replay attack prevention)
- Rate limiting
- Request/response format correctness

## Test Setup

### 1. Test Key Pair

A dedicated Ed25519 key pair is used for integration testing:

**Public Key** (configured in `docker-compose.integration.yml`):
```
Rv/5s5lttYIudkpaeGuHK2tPuwhSw7bH842bYMxjsBM=
```

**Private Key** (hardcoded in `integration-tests/integration_test.go`):
```
l4iNDGylf0wyqpv8TWoc3sFSaxJHSMuX8FeKET1ZeXRG//mzmW21gi52Slp4a4cra0+7CFLDtsfzjZtgzGOwEw==
```

⚠️ **Note:** These keys are for testing only. Never use them in production.

### 2. Server Configuration

The integration test server is configured via `docker-compose.integration.yml`:

```yaml
environment:
  - MANAGEMENT_API_AUTHORIZED_SIGNERS=Rv/5s5lttYIudkpaeGuHK2tPuwhSw7bH842bYMxjsBM=
```

This environment variable is loaded by `server/signature.go` at startup.

## Running Integration Tests

### Run All Integration Tests

```bash
make integration-test
```

### Run Only Management API Tests

```bash
TEST_NAME=TestManagementAPI make integration-test
```

### Manual Test Run

```bash
# Start services
docker compose -f docker-compose.integration.yml up -d

# Wait for services to be ready
sleep 10

# Build and run tests
docker compose -f docker-compose.integration.yml --profile test build test-runner
docker compose -f docker-compose.integration.yml --profile test run --rm test-runner \
  go test -v -tags=integration ./integration-tests -run=TestManagementAPI

# Clean up
docker compose -f docker-compose.integration.yml --profile test down -v
```

## Test Coverage

### TestManagementAPI

The main test suite includes:

#### 1. list_issuers_success
- **Tests:** Successful API call with valid signature
- **Verifies:**
  - 200 OK response
  - Correct JSON response format
  - Issuer data structure
  - At least one issuer returned

#### 2. unauthorized_signer
- **Tests:** Request signed by key NOT in authorized list
- **Verifies:**
  - 403 Forbidden response
  - Unauthorized signers are rejected

#### 3. invalid_signature
- **Tests:** Request with corrupted signature
- **Verifies:**
  - 401 Unauthorized response
  - Signature verification rejects invalid signatures

#### 4. expired_timestamp
- **Tests:** Request with timestamp > 5 minutes old
- **Verifies:**
  - 401 Unauthorized response
  - Replay attack prevention works

#### 5. missing_headers
- **Tests:** Request without required signature headers
- **Verifies:**
  - 401 Unauthorized response
  - Header validation is enforced

#### 6. rate_limiting
- **Tests:** Rapid succession of requests (70 requests)
- **Verifies:**
  - 429 Too Many Requests after limit
  - Rate limiter (60 req/min) works correctly

## Test Helper Functions

### managementAPIClient

A test client that implements the Ed25519 signing protocol:

```go
client := newManagementAPIClient("http://cbp:2416", privateKey)
resp, err := client.signedRequest("GET", "/api/v1/manage/issuers", "", nil)
```

**Features:**
- Automatically signs requests
- Adds required headers (X-Signature, X-Public-Key, X-Timestamp)
- Builds canonical signing message
- Uses Ed25519 standard library

### buildSigningMessage

Constructs the canonical message for signing:

```go
message := buildSigningMessage(method, path, rawQuery, timestamp, body)
signature := ed25519.Sign(privateKey, message)
```

**Format:** `METHOD\nPATH?QUERY\nTIMESTAMP\nBODY`

## Debugging Failed Tests

### Check Server Logs

```bash
docker compose -f docker-compose.integration.yml logs cbp
```

Look for:
- `"invalid signature"` - Signature verification failed
- `"public key not in authorized signers list"` - Authorization failed
- `"request timestamp expired"` - Timestamp validation failed

### Verify Environment Variable

```bash
docker compose -f docker-compose.integration.yml exec cbp \
  printenv MANAGEMENT_API_AUTHORIZED_SIGNERS
```

Should output: `Rv/5s5lttYIudkpaeGuHK2tPuwhSw7bH842bYMxjsBM=`

### Check Clock Synchronization

Timestamp validation requires clocks to be within ±5 minutes:

```bash
# Host time
date -u

# Container time
docker compose -f docker-compose.integration.yml exec cbp date -u
```

### Test Manually with CLI

You can use the `cbp-manage` CLI to manually test:

```bash
# Build CLI
go build -o cbp-manage ./cmd/cbp-manage

# Use test private key
export CBP_PRIVATE_KEY="l4iNDGylf0wyqpv8TWoc3sFSaxJHSMuX8FeKET1ZeXRG//mzmW21gi52Slp4a4cra0+7CFLDtsfzjZtgzGOwEw=="

# Test against integration server
export CBP_SERVER_URL=http://localhost:2416
./cbp-manage list-issuers
```

## Adding New Management API Tests

When adding new endpoints to the Management API:

1. **Add test types** - Define request/response structs in `integration-tests/integration_test.go`

2. **Add test cases** - Follow the pattern:
   ```go
   t.Run("new_endpoint_success", func(t *testing.T) {
       resp, err := client.signedRequest("POST", "/api/v1/manage/new-endpoint", "", body)
       require.NoError(t, err)
       defer resp.Body.Close()

       assert.Equal(t, http.StatusOK, resp.StatusCode)
       // Add response validation
   })
   ```

3. **Test failure cases:**
   - Unauthorized signer
   - Invalid input data
   - Missing required fields
   - Rate limiting

4. **Update documentation** - Add test description to this file

## Security Considerations

### Test Key Management

- ✅ Test keys are clearly marked as test-only
- ✅ Different from production keys
- ✅ Documented in version control (acceptable for test keys)
- ✅ No sensitive data in tests

### What Tests Don't Cover

The integration tests focus on the authentication protocol, not:
- ❌ Key rotation (no dynamic key updates)
- ❌ Advanced rate limiting scenarios (burst limits, IP spoofing)
- ❌ Load testing (performance under high concurrency)
- ❌ Security vulnerabilities (use security scanners)

## Continuous Integration

The integration tests run automatically in CI/CD:

```yaml
# Example CI configuration
steps:
  - name: Run Integration Tests
    run: make integration-test
```

**Requirements:**
- Docker and Docker Compose installed
- Sufficient resources (Kafka, Postgres, DynamoDB containers)
- ~30 seconds execution time for full suite

## Troubleshooting

### "No authorized signers configured"

**Problem:** Server starts with empty `AuthorizedSigners`

**Solution:** Verify `MANAGEMENT_API_AUTHORIZED_SIGNERS` is set in docker-compose.integration.yml

### Tests pass locally but fail in CI

**Problem:** Clock skew or network delays

**Solution:**
- Increase timestamp tolerance in tests
- Add retries for timing-sensitive tests
- Check CI environment clock synchronization

### Rate limiting tests are flaky

**Problem:** Timing-dependent behavior

**Solution:**
- Tests allow for some variance in rate limit enforcement
- Rate limiter uses sliding window (exact count depends on timing)
- Consider the test successful if SOME requests are rate limited

## References

- [Management API README](README.md) - CLI usage and protocol details
- [Testing Guide](TESTING.md) - Manual testing procedures
- [Server Signature Implementation](../../server/signature.go) - Verification logic
- [Integration Test Implementation](../../integration-tests/integration_test.go) - Test code
