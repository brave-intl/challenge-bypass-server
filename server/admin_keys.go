package server

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/brave-intl/bat-go/libs/httpsignature"
	"golang.org/x/crypto/ssh"
)

// Operators allowed to call /v1/admin. One OpenSSH authorized_keys line per
// operator; the comment must be the operator's email (it is written to the
// audit log). Adding or removing an operator is a code change + deploy, the
// same model as the subscriptions support API.
var prodAdminKeys = []string{}

var devAdminKeys = []string{}

const maxAdminBodySize = 1 << 20

// adminKeysForEnv returns the operator allowlist for env. An unknown env gets
// nil, which denies every admin request, rather than failing startup.
func adminKeysForEnv(env string) []string {
	switch env {
	case "production":
		return prodAdminKeys
	// staging uses the dev list so R1 (empty prodAdminKeys) can be smoke
	// tested there before operators are enabled in production.
	case "staging", "development", "dev", "sandbox", "local", "localtest", "test":
		return devAdminKeys
	}
	return nil
}

type adminKey struct {
	email string
	pub   httpsignature.Ed25519PubKey
}

type adminKeystore struct {
	keys map[string]adminKey // hex raw public key -> operator
}

func newAdminKeystore(lines []string) (*adminKeystore, error) {
	ks := &adminKeystore{keys: map[string]adminKey{}}
	for _, line := range lines {
		pk, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("admin key %q: %w", line, err)
		}
		if pk.Type() != ssh.KeyAlgoED25519 {
			return nil, fmt.Errorf("admin key %q: not ed25519", line)
		}
		if comment == "" {
			return nil, fmt.Errorf("admin key %q: comment must be the operator email", line)
		}
		raw := pk.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
		ks.keys[hex.EncodeToString(raw)] = adminKey{email: comment, pub: httpsignature.Ed25519PubKey(raw)}
	}
	return ks, nil
}

func (s *adminKeystore) LookupVerifier(ctx context.Context, keyID string) (context.Context, httpsignature.Verifier, error) {
	k, ok := s.keys[keyID]
	if !ok {
		return nil, nil, errors.New("admin: unknown operator key")
	}
	return ctx, k.pub, nil
}

func (s *adminKeystore) operator(keyID string) string {
	return s.keys[keyID].email
}

type adminKeyIDKey struct{}

// maxAdminClockSkew bounds how far a signed request's Date may be from now.
const maxAdminClockSkew = 10 * time.Minute

// adminSignatureMwr verifies ed25519 HTTP signatures over date, digest and
// (request-target) against the operator keystore. It mirrors bat-go's
// middleware.VerifyHTTPSignedOnly (same checks, same status codes) without
// importing that package's sentry/redis/rate-limiter dependencies.
func adminSignatureMwr(ks *adminKeystore) func(http.Handler) http.Handler {
	verifier := httpsignature.ParameterizedKeystoreVerifier{
		SignatureParams: httpsignature.SignatureParams{
			Algorithm: httpsignature.ED25519,
			Headers:   []string{"date", "digest", "(request-target)"},
		},
		Keystore: ks,
		Opts:     crypto.Hash(0),
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxAdminBodySize)
			if r.Header.Get("Signature") == "" {
				adminAuthError(w, http.StatusUnauthorized, "signature must be present")
				return
			}
			ctx, keyID, err := verifier.VerifyRequest(r)
			if err != nil {
				adminAuthError(w, http.StatusForbidden, "request signature verification failure")
				return
			}
			date, err := time.Parse(time.RFC1123, r.Header.Get("Date"))
			if err != nil {
				adminAuthError(w, http.StatusBadRequest, "invalid date header")
				return
			}
			now := time.Now()
			if date.After(now.Add(maxAdminClockSkew)) {
				adminAuthError(w, http.StatusTooEarly, "date is invalid")
				return
			}
			if date.Before(now.Add(-maxAdminClockSkew)) {
				adminAuthError(w, http.StatusRequestTimeout, "date is invalid")
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, adminKeyIDKey{}, keyID)))
		})
	}
}

func adminAuthError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": msg})
}

// adminOperator returns the email of the operator who signed r.
func adminOperator(r *http.Request, ks *adminKeystore) string {
	keyID, _ := r.Context().Value(adminKeyIDKey{}).(string)
	return ks.operator(keyID)
}
