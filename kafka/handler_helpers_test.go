package kafka

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/require"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"

	"github.com/brave-intl/challenge-bypass-server/model"
)

var nopLogger = slog.New(slog.DiscardHandler)

type fakeWriter struct {
	err  error
	msgs []kafka.Message
}

func (w *fakeWriter) WriteMessages(_ context.Context, msgs ...kafka.Message) error {
	if w.err != nil {
		return w.err
	}
	w.msgs = append(w.msgs, msgs...)
	return nil
}

// only returns the value of the single message the handler emitted.
func (w *fakeWriter) only(t *testing.T) io.Reader {
	t.Helper()
	require.Len(t, w.msgs, 1)
	return bytes.NewReader(w.msgs[0].Value)
}

func newSigningKey(t *testing.T) *crypto.SigningKey {
	t.Helper()
	key, err := crypto.RandomSigningKey()
	require.NoError(t, err)
	return key
}

func publicKeyText(t *testing.T, key *crypto.SigningKey) string {
	t.Helper()
	txt, err := key.PublicKey().MarshalText()
	require.NoError(t, err)
	return string(txt)
}

func issuerKey(t *testing.T, key *crypto.SigningKey, start, end *time.Time) model.IssuerKeys {
	t.Helper()
	txt, err := key.MarshalText()
	require.NoError(t, err)
	return model.IssuerKeys{SigningKey: txt, StartAt: start, EndAt: end}
}

func newIssuer(name string, cohort int16, keys ...model.IssuerKeys) model.Issuer {
	id := uuid.New()
	return model.Issuer{ID: &id, IssuerType: name, IssuerCohort: cohort, Version: 2, Keys: keys}
}

// blindTokens returns n client tokens and their blinded forms.
func blindTokens(t *testing.T, n int) ([]*crypto.Token, []*crypto.BlindedToken) {
	t.Helper()
	tokens := make([]*crypto.Token, n)
	blinded := make([]*crypto.BlindedToken, n)
	for i := range tokens {
		token, err := crypto.RandomToken()
		require.NoError(t, err)
		tokens[i] = token
		blinded[i] = token.Blind()
	}
	return tokens, blinded
}

func marshalAll[T interface{ MarshalText() ([]byte, error) }](t *testing.T, xs []T) []string {
	t.Helper()
	out := make([]string, len(xs))
	for i, x := range xs {
		txt, err := x.MarshalText()
		require.NoError(t, err)
		out[i] = string(txt)
	}
	return out
}
