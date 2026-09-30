package adminapi

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SignRequest signs r the way bat-go's httpsignature verifier expects
// (same scheme as brave support-cli): ed25519 over date, digest and
// (request-target). body must be the exact bytes sent.
func SignRequest(r *http.Request, body []byte, key ed25519.PrivateKey, now time.Time) {
	r.Header.Set("Date", now.UTC().Format(http.TimeFormat))
	sum := sha256.Sum256(body)
	digest := "SHA-256=" + base64.StdEncoding.EncodeToString(sum[:])
	r.Header.Set("Digest", digest)
	signing := strings.Join([]string{
		"date: " + r.Header.Get("Date"),
		"digest: " + digest,
		"(request-target): " + strings.ToLower(r.Method) + " " + r.URL.RequestURI(),
	}, "\n")
	sig := ed25519.Sign(key, []byte(signing))
	pub := key.Public().(ed25519.PublicKey)
	r.Header.Set("Signature", fmt.Sprintf(
		`keyId="%s",algorithm="ed25519",headers="date digest (request-target)",signature="%s"`,
		hex.EncodeToString(pub), base64.StdEncoding.EncodeToString(sig)))
}

// LoadPrivateKey reads an unencrypted OpenSSH ed25519 private key.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	switch v := k.(type) {
	case *ed25519.PrivateKey:
		return *v, nil
	case ed25519.PrivateKey:
		return v, nil
	}
	return nil, errors.New("private key is not ed25519")
}
