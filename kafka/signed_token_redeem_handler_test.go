package kafka

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"

	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/btd"
	"github.com/brave-intl/challenge-bypass-server/model"
	cbpServer "github.com/brave-intl/challenge-bypass-server/server"
	"github.com/brave-intl/challenge-bypass-server/utils"
)

type equivResult struct {
	eq  cbpServer.Equivalence
	err error
}

type fakeRedeemServer struct {
	issuers    []model.Issuer
	fetchErr   error
	equivs     []equivResult
	equivCalls int
	persistErr error
	persisted  []cbpServer.RedemptionV2
}

func (s *fakeRedeemServer) FetchAllIssuers() ([]model.Issuer, error) {
	return s.issuers, s.fetchErr
}

// CheckRedeemedTokenEquivalence returns s.equivs in call order and repeats the
// last one. With no equivs it reports NoEquivalence.
func (s *fakeRedeemServer) CheckRedeemedTokenEquivalence(issuer *model.Issuer, _ *crypto.TokenPreimage, payload string, offset int64) (*cbpServer.RedemptionV2, cbpServer.Equivalence, error) {
	r := equivResult{eq: cbpServer.NoEquivalence}
	if len(s.equivs) > 0 {
		r = s.equivs[min(s.equivCalls, len(s.equivs)-1)]
	}
	s.equivCalls++
	return &cbpServer.RedemptionV2{IssuerID: issuer.ID.String(), Payload: payload, Offset: offset}, r.eq, r.err
}

func (s *fakeRedeemServer) PersistRedemption(r cbpServer.RedemptionV2) error {
	if s.persistErr != nil {
		return s.persistErr
	}
	s.persisted = append(s.persisted, r)
	return nil
}

// redeemRequest returns a request that redeems a token signed by key, with a
// signature over binding.
func redeemRequest(t *testing.T, key *crypto.SigningKey, binding string) avroSchema.RedeemRequest {
	t.Helper()
	tokens, blinded := blindTokens(t, 1)
	signed, proof, err := btd.ApproveTokens(blinded, key)
	require.NoError(t, err)
	unblinded, err := proof.VerifyAndUnblind(tokens, blinded, signed, key.PublicKey())
	require.NoError(t, err)
	sig, err := unblinded[0].DeriveVerificationKey().Sign(binding)
	require.NoError(t, err)
	preimage, err := unblinded[0].Preimage().MarshalText()
	require.NoError(t, err)
	sigTxt, err := sig.MarshalText()
	require.NoError(t, err)
	return avroSchema.RedeemRequest{
		Associated_data: []byte("associated"),
		Public_key:      publicKeyText(t, key),
		Token_preimage:  string(preimage),
		Binding:         binding,
		Signature:       string(sigTxt),
	}
}

func redeemMessage(t *testing.T, reqs ...avroSchema.RedeemRequest) kafka.Message {
	t.Helper()
	var buf bytes.Buffer
	set := avroSchema.RedeemRequestSet{Request_id: "req-1", Data: reqs}
	require.NoError(t, set.Serialize(&buf))
	return kafka.Message{Value: buf.Bytes(), Offset: 7}
}

func redeemResults(t *testing.T, w *fakeWriter) avroSchema.RedeemResultSet {
	t.Helper()
	set, err := avroSchema.DeserializeRedeemResultSet(w.only(t))
	require.NoError(t, err)
	return set
}

func TestSignedTokenRedeemHandler(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	past, future := now.Add(-time.Hour), now.Add(time.Hour)

	key := newSigningKey(t)
	issuer := newIssuer("confirmation", 1, issuerKey(t, key, &past, &future))
	temporary := utils.ProcessingErrorFromError(errors.New("throttled"), true)
	permanent := utils.ProcessingErrorFromError(errors.New("bad item"), false)

	// redeem runs the handler for one request and returns the single result
	// it emitted.
	redeem := func(t *testing.T, s *fakeRedeemServer, req avroSchema.RedeemRequest) avroSchema.RedeemResult {
		t.Helper()
		w := &fakeWriter{}
		require.NoError(t, SignedTokenRedeemHandler(ctx, redeemMessage(t, req), w, s, nopLogger))
		set := redeemResults(t, w)
		assert.Equal(t, "req-1", set.Request_id)
		require.Len(t, set.Data, 1)
		return set.Data[0]
	}

	t.Run("redeems a valid token", func(t *testing.T) {
		s := &fakeRedeemServer{issuers: []model.Issuer{issuer}}
		got := redeem(t, s, redeemRequest(t, key, "binding"))
		assert.Equal(t, avroSchema.RedeemResultStatusOk, got.Status)
		assert.Equal(t, "confirmation", got.Issuer_name)
		assert.Equal(t, int32(1), got.Issuer_cohort)
		assert.Equal(t, []byte("associated"), []byte(got.Associated_data))
		require.Len(t, s.persisted, 1)
		assert.Equal(t, issuer.ID.String(), s.persisted[0].IssuerID)
		assert.Equal(t, int64(7), s.persisted[0].Offset)
	})

	t.Run("finds the key among several issuers and keys", func(t *testing.T) {
		other := newIssuer("other", 0, issuerKey(t, newSigningKey(t), &past, &future))
		rotated := newIssuer("confirmation", 1,
			issuerKey(t, newSigningKey(t), &past, &future),
			issuerKey(t, key, &past, &future),
		)
		s := &fakeRedeemServer{issuers: []model.Issuer{other, rotated}}
		got := redeem(t, s, redeemRequest(t, key, "binding"))
		assert.Equal(t, avroSchema.RedeemResultStatusOk, got.Status)
		assert.Equal(t, "confirmation", got.Issuer_name)
	})

	t.Run("reports a reused token with another binding as a duplicate", func(t *testing.T) {
		s := &fakeRedeemServer{issuers: []model.Issuer{issuer}, equivs: []equivResult{{eq: cbpServer.IDEquivalence}}}
		got := redeem(t, s, redeemRequest(t, key, "binding"))
		assert.Equal(t, avroSchema.RedeemResultStatusDuplicate_redemption, got.Status)
		assert.Equal(t, "confirmation", got.Issuer_name)
		assert.Empty(t, s.persisted)
	})

	t.Run("reports a retry with the same binding as idempotent", func(t *testing.T) {
		s := &fakeRedeemServer{issuers: []model.Issuer{issuer}, equivs: []equivResult{{eq: cbpServer.BindingEquivalence}}}
		got := redeem(t, s, redeemRequest(t, key, "binding"))
		assert.Equal(t, avroSchema.RedeemResultStatusIdempotent_redemption, got.Status)
		assert.Empty(t, s.persisted)
	})

	t.Run("rechecks equivalence when a concurrent write wins the race", func(t *testing.T) {
		for _, tc := range []struct {
			eq   cbpServer.Equivalence
			want avroSchema.RedeemResultStatus
		}{
			{cbpServer.IDEquivalence, avroSchema.RedeemResultStatusDuplicate_redemption},
			{cbpServer.BindingEquivalence, avroSchema.RedeemResultStatusIdempotent_redemption},
		} {
			s := &fakeRedeemServer{
				issuers:    []model.Issuer{issuer},
				equivs:     []equivResult{{eq: cbpServer.NoEquivalence}, {eq: tc.eq}},
				persistErr: cbpServer.ErrDuplicateRedemption,
			}
			got := redeem(t, s, redeemRequest(t, key, "binding"))
			assert.Equal(t, tc.want, got.Status)
			assert.Equal(t, 2, s.equivCalls)
		}
	})

	t.Run("reports an error when persisting fails", func(t *testing.T) {
		s := &fakeRedeemServer{issuers: []model.Issuer{issuer}, persistErr: errors.New("boom")}
		got := redeem(t, s, redeemRequest(t, key, "binding"))
		assert.Equal(t, avroSchema.RedeemResultStatusError, got.Status)
		assert.Equal(t, "confirmation", got.Issuer_name)
	})

	t.Run("rejects as unverified", func(t *testing.T) {
		wrongBinding := redeemRequest(t, key, "binding")
		wrongBinding.Binding = "another binding"

		notStarted := newIssuer("confirmation", 1, issuerKey(t, key, &future, &future))
		ended := newIssuer("confirmation", 1, issuerKey(t, key, &past, &past))
		expired := newIssuer("confirmation", 1, issuerKey(t, key, &past, &future))
		expired.ExpiresAt.Valid, expired.ExpiresAt.Time = true, past
		halfBounded := newIssuer("confirmation", 1, issuerKey(t, key, &past, nil))

		for name, tc := range map[string]struct {
			issuers []model.Issuer
			req     avroSchema.RedeemRequest
		}{
			"a signature over another binding": {[]model.Issuer{issuer}, wrongBinding},
			"an unknown public key":            {[]model.Issuer{issuer}, redeemRequest(t, newSigningKey(t), "binding")},
			"a key that has not started":       {[]model.Issuer{notStarted}, redeemRequest(t, key, "binding")},
			"a key that has ended":             {[]model.Issuer{ended}, redeemRequest(t, key, "binding")},
			"an expired issuer":                {[]model.Issuer{expired}, redeemRequest(t, key, "binding")},
			"a key with only one time bound":   {[]model.Issuer{halfBounded}, redeemRequest(t, key, "binding")},
		} {
			t.Run(name, func(t *testing.T) {
				s := &fakeRedeemServer{issuers: tc.issuers}
				got := redeem(t, s, tc.req)
				assert.Equal(t, avroSchema.RedeemResultStatusUnverified, got.Status)
				assert.Empty(t, got.Issuer_name)
				assert.Zero(t, s.equivCalls)
				assert.Empty(t, s.persisted)
			})
		}
	})

	t.Run("reports an error for a request missing a field", func(t *testing.T) {
		for name, clear := range map[string]func(*avroSchema.RedeemRequest){
			"public key": func(r *avroSchema.RedeemRequest) { r.Public_key = "" },
			"preimage":   func(r *avroSchema.RedeemRequest) { r.Token_preimage = "" },
			"signature":  func(r *avroSchema.RedeemRequest) { r.Signature = "" },
			"binding":    func(r *avroSchema.RedeemRequest) { r.Binding = "" },
		} {
			t.Run(name, func(t *testing.T) {
				req := redeemRequest(t, key, "binding")
				clear(&req)
				got := redeem(t, &fakeRedeemServer{issuers: []model.Issuer{issuer}}, req)
				assert.Equal(t, avroSchema.RedeemResultStatusError, got.Status)
				assert.Equal(t, []byte("associated"), []byte(got.Associated_data))
			})
		}
	})

	// A permanent failure emits an error result in place of the request's
	// results and returns nil, so the message is committed.
	t.Run("emits an error result for a permanent failure", func(t *testing.T) {
		badPreimage := redeemRequest(t, key, "binding")
		badPreimage.Token_preimage = "not base64"
		badSignature := redeemRequest(t, key, "binding")
		badSignature.Signature = "not base64"
		valid := redeemRequest(t, key, "binding")

		for name, tc := range map[string]struct {
			s   *fakeRedeemServer
			msg kafka.Message
		}{
			"an undecodable message":    {&fakeRedeemServer{}, kafka.Message{Value: []byte{0xff}}},
			"more than one request":     {&fakeRedeemServer{issuers: []model.Issuer{issuer}}, redeemMessage(t, valid, valid)},
			"a permanent fetch error":   {&fakeRedeemServer{fetchErr: permanent}, redeemMessage(t, valid)},
			"a bad preimage":            {&fakeRedeemServer{issuers: []model.Issuer{issuer}}, redeemMessage(t, badPreimage)},
			"a bad signature":           {&fakeRedeemServer{issuers: []model.Issuer{issuer}}, redeemMessage(t, badSignature)},
			"a permanent dynamo error":  {&fakeRedeemServer{issuers: []model.Issuer{issuer}, equivs: []equivResult{{err: permanent}}}, redeemMessage(t, valid)},
			"a permanent recheck error": {&fakeRedeemServer{issuers: []model.Issuer{issuer}, equivs: []equivResult{{}, {err: permanent}}, persistErr: cbpServer.ErrDuplicateRedemption}, redeemMessage(t, valid)},
		} {
			t.Run(name, func(t *testing.T) {
				w := &fakeWriter{}
				require.NoError(t, SignedTokenRedeemHandler(ctx, tc.msg, w, tc.s, nopLogger))
				set := redeemResults(t, w)
				require.Len(t, set.Data, 1)
				assert.Equal(t, avroSchema.RedeemResultStatusError, set.Data[0].Status)
				assert.Empty(t, tc.s.persisted)
			})
		}
	})

	// A temporary failure returns the error and emits nothing, so the message
	// is not committed and is retried.
	t.Run("returns a temporary failure without emitting", func(t *testing.T) {
		valid := redeemRequest(t, key, "binding")
		for name, s := range map[string]*fakeRedeemServer{
			"fetching issuers":     {fetchErr: temporary},
			"checking equivalence": {issuers: []model.Issuer{issuer}, equivs: []equivResult{{err: temporary}}},
			"rechecking after a race": {
				issuers:    []model.Issuer{issuer},
				equivs:     []equivResult{{}, {err: temporary}},
				persistErr: cbpServer.ErrDuplicateRedemption,
			},
		} {
			t.Run(name, func(t *testing.T) {
				w := &fakeWriter{}
				err := SignedTokenRedeemHandler(ctx, redeemMessage(t, valid), w, s, nopLogger)
				assert.ErrorIs(t, err, temporary)
				assert.Empty(t, w.msgs)
			})
		}
	})

	t.Run("returns an emit failure", func(t *testing.T) {
		w := &fakeWriter{err: errors.New("broker down")}
		s := &fakeRedeemServer{issuers: []model.Issuer{issuer}}
		err := SignedTokenRedeemHandler(ctx, redeemMessage(t, redeemRequest(t, key, "binding")), w, s, nopLogger)
		assert.ErrorIs(t, err, w.err)
	})
}

func TestIssuerTimeIsNotValid(t *testing.T) {
	now := time.Now()
	past, future, zero := now.Add(-time.Hour), now.Add(time.Hour), time.Time{}

	for name, tc := range map[string]struct {
		start, end *time.Time
		want       bool
	}{
		"no bounds":         {nil, nil, false},
		"inside its window": {&past, &future, false},
		"zero bounds":       {&zero, &zero, false},
		"not started":       {&future, &future, true},
		"ended":             {&past, &past, true},
		"only a start":      {&past, nil, true},
		"only an end":       {nil, &future, true},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, issuerTimeIsNotValid(tc.start, tc.end))
		})
	}
}
