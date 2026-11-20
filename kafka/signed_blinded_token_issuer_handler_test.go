package kafka

import (
	"bytes"
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"

	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/model"
	"github.com/brave-intl/challenge-bypass-server/utils"
)

type fakeSignServer struct {
	issuer    *model.Issuer
	err       error
	rotateErr error
	rotations int
	gotType   string
	gotCohort int16
}

func (s *fakeSignServer) GetLatestIssuerKafka(issuerType string, issuerCohort int16) (*model.Issuer, error) {
	s.gotType, s.gotCohort = issuerType, issuerCohort
	return s.issuer, s.err
}

func (s *fakeSignServer) RotateIssuersV3() error {
	s.rotations++
	return s.rotateErr
}

func signMessage(t *testing.T, reqs ...avroSchema.SigningRequest) kafka.Message {
	t.Helper()
	var buf bytes.Buffer
	set := avroSchema.SigningRequestSet{Request_id: "req-1", Data: reqs}
	require.NoError(t, set.Serialize(&buf))
	return kafka.Message{Value: buf.Bytes()}
}

func signResults(t *testing.T, w *fakeWriter) avroSchema.SigningResultV2Set {
	t.Helper()
	set, err := avroSchema.DeserializeSigningResultV2Set(w.only(t))
	require.NoError(t, err)
	return set
}

// verifySigned checks that res signed blinded with the key whose public key
// res names, by verifying its DLEQ proof and unblinding.
func verifySigned(t *testing.T, res avroSchema.SigningResultV2, tokens []*crypto.Token, blinded []*crypto.BlindedToken) {
	t.Helper()
	require.Equal(t, avroSchema.SigningResultV2StatusOk, res.Status)
	require.Equal(t, marshalAll(t, blinded), res.Blinded_tokens)

	var pub crypto.PublicKey
	require.NoError(t, pub.UnmarshalText([]byte(res.Issuer_public_key)))
	var proof crypto.BatchDLEQProof
	require.NoError(t, proof.UnmarshalText([]byte(res.Proof)))
	signed := make([]*crypto.SignedToken, len(res.Signed_tokens))
	for i, s := range res.Signed_tokens {
		signed[i] = &crypto.SignedToken{}
		require.NoError(t, signed[i].UnmarshalText([]byte(s)))
	}
	_, err := proof.VerifyAndUnblind(tokens, blinded, signed, &pub)
	require.NoError(t, err)
}

func TestSignedBlindedTokenIssuerHandler(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	past, future := now.Add(-time.Hour), now.Add(time.Hour)

	key := newSigningKey(t)
	issuer := newIssuer("10BAT", 1, issuerKey(t, key, &past, &future))
	temporary := utils.ProcessingErrorFromError(errors.New("db down"), true)

	request := func(blinded []*crypto.BlindedToken) avroSchema.SigningRequest {
		return avroSchema.SigningRequest{
			Associated_data: []byte("associated"),
			Blinded_tokens:  marshalAll(t, blinded),
			Issuer_type:     "10BAT",
			Issuer_cohort:   1,
		}
	}

	// sign runs the handler for one request and returns the results it emitted.
	sign := func(t *testing.T, s *fakeSignServer, req avroSchema.SigningRequest) []avroSchema.SigningResultV2 {
		t.Helper()
		w := &fakeWriter{}
		require.NoError(t, SignedBlindedTokenIssuerHandler(ctx, signMessage(t, req), w, s, nopLogger))
		set := signResults(t, w)
		assert.Equal(t, "req-1", set.Request_id)
		return set.Data
	}

	t.Run("signs with the current key", func(t *testing.T) {
		tokens, blinded := blindTokens(t, 3)
		s := &fakeSignServer{issuer: &issuer}
		got := sign(t, s, request(blinded))
		require.Len(t, got, 1)
		verifySigned(t, got[0], tokens, blinded)
		assert.Equal(t, publicKeyText(t, key), got[0].Issuer_public_key)
		assert.Equal(t, []byte("associated"), []byte(got[0].Associated_data))
		assert.Equal(t, "10BAT", s.gotType)
		assert.Equal(t, int16(1), s.gotCohort)
	})

	t.Run("signs with the newest started key after a rotation", func(t *testing.T) {
		next := newSigningKey(t)
		rotated := newIssuer("10BAT", 1,
			issuerKey(t, key, &past, &future),
			issuerKey(t, next, &now, &future),
		)
		tokens, blinded := blindTokens(t, 2)
		got := sign(t, &fakeSignServer{issuer: &rotated}, request(blinded))
		require.Len(t, got, 1)
		verifySigned(t, got[0], tokens, blinded)
		assert.Equal(t, publicKeyText(t, next), got[0].Issuer_public_key)
	})

	t.Run("keeps signing with the old key until the new one starts", func(t *testing.T) {
		pending := newIssuer("10BAT", 1,
			issuerKey(t, key, &past, &future),
			issuerKey(t, newSigningKey(t), &future, &future),
		)
		_, blinded := blindTokens(t, 1)
		got := sign(t, &fakeSignServer{issuer: &pending}, request(blinded))
		require.Len(t, got, 1)
		assert.Equal(t, publicKeyText(t, key), got[0].Issuer_public_key)
	})

	t.Run("signs a time-aware issuer per key and period", func(t *testing.T) {
		const buffer, perKey = 2, 2
		k1, k2 := newSigningKey(t), newSigningKey(t)
		d1, d2, d3 := now, now.AddDate(0, 0, 1), now.AddDate(0, 0, 2)
		v3 := newIssuer("time-aware", 1, issuerKey(t, k1, &d1, &d2), issuerKey(t, k2, &d2, &d3))
		v3.Version, v3.Buffer = 3, buffer

		tokens, blinded := blindTokens(t, buffer*perKey)
		got := sign(t, &fakeSignServer{issuer: &v3}, request(blinded))
		require.Len(t, got, buffer)

		// The first slice of tokens goes to the last key.
		for i, want := range []struct {
			key      *crypto.SigningKey
			from, to time.Time
		}{{k2, d2, d3}, {k1, d1, d2}} {
			verifySigned(t, got[i], tokens[i*perKey:(i+1)*perKey], blinded[i*perKey:(i+1)*perKey])
			assert.Equal(t, publicKeyText(t, want.key), got[i].Issuer_public_key)
			assert.Equal(t, want.from.Format(time.RFC3339), got[i].Valid_from.String)
			assert.Equal(t, want.to.Format(time.RFC3339), got[i].Valid_to.String)
		}
	})

	t.Run("reports an error result", func(t *testing.T) {
		_, blinded := blindTokens(t, 1)
		noKeys := newIssuer("10BAT", 1)
		v3 := newIssuer("time-aware", 1, issuerKey(t, key, &past, &future))
		v3.Version, v3.Buffer = 3, 2

		for name, tc := range map[string]struct {
			issuer *model.Issuer
			edit   func(*avroSchema.SigningRequest)
		}{
			"with no blinded tokens":            {&issuer, func(r *avroSchema.SigningRequest) { r.Blinded_tokens = nil }},
			"for a cohort above int16":          {&issuer, func(r *avroSchema.SigningRequest) { r.Issuer_cohort = math.MaxInt16 + 1 }},
			"for a cohort below int16":          {&issuer, func(r *avroSchema.SigningRequest) { r.Issuer_cohort = math.MinInt16 - 1 }},
			"for an undecodable token":          {&issuer, func(r *avroSchema.SigningRequest) { r.Blinded_tokens = []string{"not a token"} }},
			"for an issuer with no keys":        {&noKeys, func(*avroSchema.SigningRequest) {}},
			"for a count not a buffer multiple": {&v3, func(*avroSchema.SigningRequest) {}},
		} {
			t.Run(name, func(t *testing.T) {
				req := request(blinded)
				tc.edit(&req)
				got := sign(t, &fakeSignServer{issuer: tc.issuer}, req)
				require.Len(t, got, 1)
				assert.Equal(t, avroSchema.SigningResultV2StatusError, got[0].Status)
				assert.Empty(t, got[0].Signed_tokens)
				assert.Equal(t, []byte("associated"), []byte(got[0].Associated_data))
			})
		}
	})

	t.Run("reports an invalid issuer", func(t *testing.T) {
		stopped := issuer
		stopped.StopIssuingAt = &past
		for name, s := range map[string]*fakeSignServer{
			"that does not exist": {err: errors.New("no such issuer")},
			"that is retired":     {issuer: &stopped},
		} {
			t.Run(name, func(t *testing.T) {
				_, blinded := blindTokens(t, 1)
				got := sign(t, s, request(blinded))
				require.Len(t, got, 1)
				assert.Equal(t, avroSchema.SigningResultV2StatusInvalid_issuer, got[0].Status)
				assert.Empty(t, got[0].Signed_tokens)
			})
		}
	})

	t.Run("emits an error result for a malformed message", func(t *testing.T) {
		_, blinded := blindTokens(t, 1)
		for name, msg := range map[string]kafka.Message{
			"undecodable":           {Value: []byte{0xff}},
			"more than one request": signMessage(t, request(blinded), request(blinded)),
		} {
			t.Run(name, func(t *testing.T) {
				w := &fakeWriter{}
				require.NoError(t, SignedBlindedTokenIssuerHandler(ctx, msg, w, &fakeSignServer{issuer: &issuer}, nopLogger))
				set := signResults(t, w)
				require.Len(t, set.Data, 1)
				assert.Equal(t, avroSchema.SigningResultV2StatusError, set.Data[0].Status)
			})
		}
	})

	t.Run("returns a temporary issuer lookup failure without emitting", func(t *testing.T) {
		_, blinded := blindTokens(t, 1)
		w := &fakeWriter{}
		err := SignedBlindedTokenIssuerHandler(ctx, signMessage(t, request(blinded)), w, &fakeSignServer{err: temporary}, nopLogger)
		assert.ErrorIs(t, err, temporary)
		assert.Empty(t, w.msgs)
	})

	t.Run("rotates and retries when a time-aware issuer lacks keys", func(t *testing.T) {
		v3 := newIssuer("time-aware", 1, issuerKey(t, key, &past, &future))
		v3.Version, v3.Buffer = 3, 2
		_, blinded := blindTokens(t, 2)

		for name, rotateErr := range map[string]error{"rotation works": nil, "rotation fails": errors.New("boom")} {
			t.Run(name, func(t *testing.T) {
				w := &fakeWriter{}
				s := &fakeSignServer{issuer: &v3, rotateErr: rotateErr}
				err := SignedBlindedTokenIssuerHandler(ctx, signMessage(t, request(blinded)), w, s, nopLogger)
				assert.Error(t, err)
				assert.Equal(t, 1, s.rotations)
				assert.Empty(t, w.msgs)
			})
		}
	})

	t.Run("returns an emit failure", func(t *testing.T) {
		_, blinded := blindTokens(t, 1)
		w := &fakeWriter{err: errors.New("broker down")}
		err := SignedBlindedTokenIssuerHandler(ctx, signMessage(t, request(blinded)), w, &fakeSignServer{issuer: &issuer}, nopLogger)
		assert.ErrorIs(t, err, w.err)
	})
}
