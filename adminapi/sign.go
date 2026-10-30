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

// SignRequest signs r the way bat-go's httpsignature verifier expects. It
// uses the same scheme as brave support-cli, ed25519 over date, digest and
// (request-target). The digest covers r.Body, which is read and restored.
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
