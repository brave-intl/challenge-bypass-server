# Testing the Management CLI

This guide walks through testing the CLI tool against a local server.

## Prerequisites

- Server running locally (default port 2416)
- Go toolchain installed
- CLI built: `go build -o cbp-manage ./cmd/cbp-manage`

## Test Flow

### 1. Generate Test Keys

```bash
./cbp-manage keygen
```

Example output:
```
Generated Ed25519 Key Pair

Public Key (add to server's AuthorizedSigners):
uFa4g7dbDXbFBySvNfZJFG/LrkFyuHJ/Jy0+B+ZORmM=

Private Key (keep secure!):
i9j/UdbQjvvWP8doJVjdpkZ9aem7Ox8+GLSqKmzm0OK4VriDt1sNdsUHJK819kkUb8uuQXK4cn8nLT4H5k5GYw==
```

### 2. Add Public Key to Server

Edit `server/signature.go` and add the public key to `AuthorizedSigners`:

```go
var AuthorizedSigners = []string{
    "uFa4g7dbDXbFBySvNfZJFG/LrkFyuHJ/Jy0+B+ZORmM=", // Add your public key here
}
```

### 3. Restart the Server

```bash
# Stop the server if running (Ctrl+C)

# Rebuild and start
go build -o challenge-bypass-server .
./challenge-bypass-server -p 2416
```

### 4. Configure CLI

```bash
# Save the private key
mkdir -p ~/.cbp
echo 'i9j/UdbQjvvWP8doJVjdpkZ9aem7Ox8+GLSqKmzm0OK4VriDt1sNdsUHJK819kkUb8uuQXK4cn8nLT4H5k5GYw==' > ~/.cbp/private_key
chmod 600 ~/.cbp/private_key

# Export environment variable
export CBP_PRIVATE_KEY_FILE=~/.cbp/private_key
export CBP_SERVER_URL=http://localhost:2416
```

### 5. Test List Issuers

```bash
./cbp-manage list-issuers
```

Expected output (if server has issuers):
```
Found 2 issuer(s)

Issuer 1:
  ID:         550e8400-e29b-41d4-a716-446655440000
  Name:       brave-rewards
  Cohort:     1
  MaxTokens:  40
  Version:    3
  ...
```

## Verification Tests

### Test 1: Signature Verification

The server should accept the signed request. Check server logs for:
```
[verification successful]
```

### Test 2: Unauthorized Key

Generate a second key pair but DON'T add it to AuthorizedSigners:

```bash
./cbp-manage keygen > test_key.txt
export CBP_PRIVATE_KEY=$(grep "Private Key" -A 1 test_key.txt | tail -n 1)
./cbp-manage list-issuers
```

Expected: Should fail with 403 Forbidden

### Test 3: Invalid Signature

Modify the private key slightly:

```bash
export CBP_PRIVATE_KEY="invalid_key_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
./cbp-manage list-issuers
```

Expected: Should fail with 401 Unauthorized or decode error

### Test 4: Rate Limiting

Make many requests rapidly:

```bash
for i in {1..70}; do
  ./cbp-manage list-issuers > /dev/null 2>&1
  echo "Request $i"
done
```

Expected: Should get rate limited (429) after ~60 requests within a minute

### Test 5: Expired Timestamp

This requires modifying the CLI to use an old timestamp. For now, verify that requests work within the 5-minute window.

## Protocol Verification

### Verify Signing Message Construction

Add debug output to the CLI to see the canonical message:

```go
// In buildSigningMessage function
func buildSigningMessage(method, path, rawQuery string, timestamp time.Time, body []byte) []byte {
    timestampStr := strconv.FormatInt(timestamp.Unix(), 10)
    requestTarget := path
    if rawQuery != "" {
        requestTarget = fmt.Sprintf("%s?%s", path, rawQuery)
    }
    message := fmt.Sprintf("%s\n%s\n%s\n", method, requestTarget, timestampStr)

    // DEBUG: Print canonical message
    fmt.Fprintf(os.Stderr, "DEBUG: Canonical message:\n%s[body length: %d]\n", message, len(body))

    return append([]byte(message), body...)
}
```

Expected format for `GET /api/v1/manage/issuers`:
```
GET
/api/v1/manage/issuers
1707851234

```

### Verify Headers

Use `curl` with verbose output to see headers:

```bash
# Extract values from CLI run
PUBLIC_KEY="your-public-key-base64"
SIGNATURE="signature-base64"
TIMESTAMP="unix-timestamp"

curl -v \
  -H "X-Signature: $SIGNATURE" \
  -H "X-Public-Key: $PUBLIC_KEY" \
  -H "X-Timestamp: $TIMESTAMP" \
  http://localhost:2416/api/v1/manage/issuers
```

## Troubleshooting

### Issue: "Failed to load private key"

**Solution:**
- Verify `CBP_PRIVATE_KEY_FILE` points to correct file
- Check file permissions: `ls -la ~/.cbp/private_key`
- Verify file contains valid base64: `cat ~/.cbp/private_key | base64 -d | wc -c` should output 64

### Issue: "request failed with status 403"

**Cause:** Public key not in AuthorizedSigners

**Solution:**
1. Run `./cbp-manage keygen` and note the public key
2. Add public key to `server/signature.go` `AuthorizedSigners`
3. Rebuild and restart server

### Issue: "request failed with status 401"

**Causes:**
- Signature verification failed
- Timestamp too old/new (> 5 minutes difference)
- Private/public key mismatch

**Solution:**
1. Ensure server and client clocks are synchronized: `date`
2. Verify you're using matching key pair
3. Check server logs for specific error

### Issue: "no authorized signers configured"

**Cause:** Server's `AuthorizedSigners` is empty

**Solution:** Add at least one public key to `AuthorizedSigners` in `server/signature.go`

## Integration Test Script

Create a test script to automate testing:

```bash
#!/bin/bash
# test-cli.sh

set -e

echo "=== Testing Management CLI ==="

# Generate keys
echo "1. Generating keys..."
./cbp-manage keygen > test_keys.txt
PUBLIC_KEY=$(grep "Public Key" -A 1 test_keys.txt | tail -n 1)
PRIVATE_KEY=$(grep "Private Key" -A 1 test_keys.txt | tail -n 1)

echo "Public Key: $PUBLIC_KEY"

# Setup
echo "2. Setting up..."
mkdir -p ~/.cbp-test
echo "$PRIVATE_KEY" > ~/.cbp-test/private_key
chmod 600 ~/.cbp-test/private_key

# Test
echo "3. Testing list-issuers..."
export CBP_PRIVATE_KEY_FILE=~/.cbp-test/private_key
export CBP_SERVER_URL=http://localhost:2416

if ./cbp-manage list-issuers; then
    echo "✓ CLI test passed"
else
    echo "✗ CLI test failed"
    echo ""
    echo "Make sure:"
    echo "  1. Server is running on port 2416"
    echo "  2. Public key '$PUBLIC_KEY' is in server/signature.go AuthorizedSigners"
    echo "  3. Server has been restarted after adding the key"
    exit 1
fi

# Cleanup
rm -rf ~/.cbp-test
rm test_keys.txt

echo "=== All tests passed ==="
```

Make it executable and run:
```bash
chmod +x test-cli.sh
./test-cli.sh
```

## Success Criteria

The CLI implementation is correct if:

- ✅ Keygen produces valid Ed25519 key pairs
- ✅ Authorized requests succeed (200 OK)
- ✅ Unauthorized keys fail (403 Forbidden)
- ✅ Invalid signatures fail (401 Unauthorized)
- ✅ Rate limiting works (429 after 60 req/min)
- ✅ Response data is correctly parsed and displayed
- ✅ Signing message format matches server expectation

## Next Steps

After successful testing:

1. Document any issues found
2. Consider adding automated tests
3. Test against staging/production environments
4. Document key management procedures
5. Implement additional commands (create, rotate, delete)
