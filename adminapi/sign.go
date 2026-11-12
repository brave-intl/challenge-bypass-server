package adminapi

import (
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/brave-intl/bat-go/libs/httpsignature"
	"golang.org/x/crypto/ssh"
)

// SignRequest signs r for bat-go's httpsignature verifier with ed25519 over
// date, digest and (request-target), the scheme brave support-cli uses.
// SignRequest reads r.Body to compute the digest and then restores r.Body.
func SignRequest(r *http.Request, key ed25519.PrivateKey, now time.Time) error {
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("signing key is not ed25519")
	}
	r.Header.Set("Date", now.UTC().Format(http.TimeFormat))
	s := httpsignature.ParameterizedSignator{
		SignatureParams: httpsignature.SignatureParams{
			Algorithm: httpsignature.ED25519,
			KeyID:     hex.EncodeToString(pub),
			Headers:   []string{"date", "digest", "(request-target)"},
		},
		Signator: key,
		Opts:     crypto.Hash(0),
	}
	return s.SignRequest(r)
}

// LoadPrivateKey reads an OpenSSH ed25519 private key. If the key is
// encrypted, LoadPrivateKey calls passphrase to get the passphrase.
func LoadPrivateKey(path string, passphrase func() ([]byte, error)) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := ssh.ParseRawPrivateKey(raw)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		var pass []byte
		if pass, err = passphrase(); err != nil {
			return nil, err
		}
		k, err = ssh.ParseRawPrivateKeyWithPassphrase(raw, pass)
	}
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
