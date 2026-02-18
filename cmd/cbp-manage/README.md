# cbp-manage - Challenge Bypass Server Management CLI

A command-line tool for managing the Challenge Bypass Server via its Management API.

## Features

- **Ed25519 Signature Authentication** - Implements the complete signing protocol
- **Key Generation** - Generate Ed25519 key pairs for API authentication
- **List Issuers** - Query all issuers and their keys

## Installation

```bash
# From the repository root
go build -o cbp-manage ./cmd/cbp-manage

# Or install to $GOPATH/bin
go install ./cmd/cbp-manage
```

## Quick Start

### 1. Generate a Key Pair

```bash
./cbp-manage keygen
```

This outputs:
- Public key (add to server's `AuthorizedSigners` list)
- Private key (keep secure!)

### 2. Save Your Private Key

```bash
mkdir -p ~/.cbp
echo 'YOUR_PRIVATE_KEY_HERE' > ~/.cbp/private_key
chmod 600 ~/.cbp/private_key
```

### 3. Configure the Server

Add your public key to `server/signature.go`:

```go
var AuthorizedSigners = []string{
    "YOUR_PUBLIC_KEY_HERE",
}
```

Restart the server.

### 4. Use the CLI

```bash
export CBP_PRIVATE_KEY_FILE=~/.cbp/private_key
export CBP_SERVER_URL=http://localhost:2416  # optional, this is the default

./cbp-manage list-issuers
```

## Commands

### `keygen`

Generate a new Ed25519 key pair.

```bash
./cbp-manage keygen
```

**Output:**
- Public key (base64-encoded, 32 bytes)
- Private key (base64-encoded, 64 bytes)

**Important:** Keep your private key secure! It grants full administrative access to the Management API.

### `list-issuers`

List all issuers and their associated keys.

```bash
./cbp-manage list-issuers
```

**Example Output:**
```
Found 2 issuer(s)

Issuer 1:
  ID:         550e8400-e29b-41d4-a716-446655440000
  Name:       brave-rewards
  Cohort:     1
  MaxTokens:  40
  Version:    3
  Keys:       2 key(s)
    Key 1:
      PublicKey: BGZhPJCl5DG5FJKmBPSuy...
      Cohort:    1
      StartAt:   2024-01-15T00:00:00Z
      EndAt:     2024-02-15T00:00:00Z
```

## Configuration

Configuration is done via environment variables:

| Variable               | Description                                   | Default                      |
|------------------------|-----------------------------------------------|------------------------------|
| `CBP_SERVER_URL`       | Server base URL                               | `http://localhost:2416`      |
| `CBP_PRIVATE_KEY_FILE` | Path to file containing base64-encoded key    | (none, required)             |
| `CBP_PRIVATE_KEY`      | Base64-encoded private key (alternative)      | (none)                       |

**Priority:** `CBP_PRIVATE_KEY_FILE` is checked first, then `CBP_PRIVATE_KEY`.

## Protocol Implementation

This CLI implements the Ed25519 signature-based authentication protocol:

### Signing Algorithm

1. **Build canonical request:**
   ```
   METHOD + "\n" + PATH + QUERY + "\n" + TIMESTAMP + "\n" + BODY
   ```

2. **Sign with Ed25519:**
   ```
   signature = Ed25519-Sign(private_key, canonical_request)
   ```

3. **Add headers:**
   - `X-Signature`: base64(signature)
   - `X-Public-Key`: base64(public_key)
   - `X-Timestamp`: unix_timestamp

### Security Properties

- **Authentication**: Only holders of authorized private keys can make requests
- **Integrity**: Signature covers all request components (prevents tampering)
- **Replay Prevention**: 5-minute timestamp window (server validates ±5 minutes)
- **Standard Cryptography**: Uses Go's `crypto/ed25519` (RFC 8032)

## Development

### Building

```bash
go build -o cbp-manage ./cmd/cbp-manage
```

### Testing Against Local Server

```bash
# Start the server
./challenge-bypass-server -p 2416

# In another terminal, generate keys
./cbp-manage keygen

# Add the public key to server/signature.go and restart server

# Test the CLI
export CBP_PRIVATE_KEY_FILE=~/.cbp/private_key
./cbp-manage list-issuers
```

## Security Considerations

1. **Private Key Storage:**
   - Store private keys in secure locations
   - Use `chmod 600` to restrict file permissions
   - Never commit private keys to version control

2. **Key Distribution:**
   - Distribute private keys through secure channels only
   - Consider using key management systems for production

3. **Network Security:**
   - Use HTTPS in production (configure `CBP_SERVER_URL` with https://)
   - The signature provides authentication/integrity, not confidentiality

4. **Key Rotation:**
   - Authorized signers are configured at server startup
   - Key rotation requires server configuration change and restart

## Troubleshooting

### "Failed to load private key"

- Ensure `CBP_PRIVATE_KEY_FILE` or `CBP_PRIVATE_KEY` is set
- Verify the key file exists and is readable
- Check that the key is valid base64

### "request failed with status 401" or "request failed with status 403"

- **401 Unauthorized**: Signature verification failed
  - Check that your private key matches a public key in `AuthorizedSigners`
  - Ensure server and client clocks are synchronized (±5 minutes)
  - Verify you're using the correct server URL

- **403 Forbidden**: Public key not in authorized signers list
  - Add your public key to `server/signature.go` `AuthorizedSigners`
  - Restart the server

### "request failed with status 429"

- Rate limit exceeded (default: 60 requests/minute per IP)
- Wait and retry

## Examples

### Complete Workflow

```bash
# 1. Generate keys
./cbp-manage keygen > keys.txt

# 2. Extract and save private key
grep "Private Key" -A 1 keys.txt | tail -n 1 > ~/.cbp/private_key
chmod 600 ~/.cbp/private_key

# 3. Extract public key and add to server
grep "Public Key" -A 1 keys.txt | tail -n 1
# (Add to server/signature.go, restart server)

# 4. Configure and use
export CBP_PRIVATE_KEY_FILE=~/.cbp/private_key
./cbp-manage list-issuers
```

### Using Docker

If the server is running in Docker:

```bash
export CBP_SERVER_URL=http://localhost:2416
export CBP_PRIVATE_KEY_FILE=~/.cbp/private_key
./cbp-manage list-issuers
```

## Future Commands

The following commands are planned but not yet implemented:

- `create-issuer` - Create a new issuer
- `rotate-issuer` - Rotate issuer keys
- `delete-issuer` - Delete an issuer
- `get-issuer` - Get details for a specific issuer

## Contributing

When adding new commands:

1. Implement the command handler function
2. Add the command to the switch statement in `main()`
3. Update this README with usage instructions
4. Ensure the command follows the signing protocol

## License

See repository LICENSE file.
