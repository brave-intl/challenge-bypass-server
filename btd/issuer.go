package btd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	"github.com/prometheus/client_golang/prometheus"
)

var acceptLegacyDerivation = os.Getenv("ACCEPT_LEGACY_TOKENS") != "false"

var (
	// ErrInvalidMAC - the mac was invalid
	ErrInvalidMAC = errors.New("binding MAC didn't match derived MAC")
	// ErrIdentityPreimage - HashToGroup(preimage) produced the group identity
	// element, which RFC 9497 Section 3.3.1 requires be rejected (InvalidInputError)
	ErrIdentityPreimage = errors.New("token preimage hashes to the identity element")
	// ErrInvalidBatchProof - the batch proof was invalid
	ErrInvalidBatchProof = errors.New("new batch proof for signed tokens is invalid")

	latencyBuckets = []float64{.25, .5, 1, 2.5, 5, 10}

	verifyTokenRedemptionCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "crypto_verify_redemption_token_counter",
		Help: "counter for number of times redemption token verification happens",
	})

	verifyTokenDeriveKeyDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "crypto_derive_verify_token_key_duration",
		Help:    "duration for deriving a token verification key",
		Buckets: latencyBuckets,
	})

	verifyTokenSignatureDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "crypto_verify_token_signature_duration",
		Help:    "duration for deriving a token verification key",
		Buckets: latencyBuckets,
	})

	signTokenCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "crypto_sign_token_counter",
		Help: "count for signing a token",
	})
	signTokenDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "crypto_sign_token_duration",
		Help:    "duration for signing a token",
		Buckets: latencyBuckets,
	})
	blindedTokenCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "crypto_blinded_token_counter",
		Help: "count for signing a token",
	})

	createBatchProofDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "crypto_create_dleq_proof_duration",
		Help:    "Creation of the DLEQ blinded proof",
		Buckets: latencyBuckets,
	})
	verifyBatchProofDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "crypto_verify_dleq_proof_duration",
		Help:    "Verify of the DLEQ blinded proof",
		Buckets: latencyBuckets,
	})
)

func init() {
	prometheus.MustRegister(blindedTokenCounter)
	prometheus.MustRegister(createBatchProofDuration)
	prometheus.MustRegister(verifyBatchProofDuration)
	prometheus.MustRegister(signTokenDuration)
	prometheus.MustRegister(signTokenCounter)

	prometheus.MustRegister(verifyTokenRedemptionCounter)
	prometheus.MustRegister(verifyTokenDeriveKeyDuration)
	prometheus.MustRegister(verifyTokenSignatureDuration)
}

// ApproveTokens applies the issuer's secret key to each token in the request.
// It returns an array of marshaled approved values along with a batch DLEQ proof.
func ApproveTokens(blindedTokens []*crypto.BlindedToken, key *crypto.SigningKey) ([]*crypto.SignedToken, *crypto.BatchDLEQProof, error) {
	var err error
	if len(blindedTokens) < 1 {
		err = errors.New("provided blindedTokens array was empty")
		return []*crypto.SignedToken{}, nil, err
	}

	blindedTokenCounter.Add(float64(len(blindedTokens)))
	signedTokens := make([]*crypto.SignedToken, len(blindedTokens))
	for i, blindedToken := range blindedTokens {
		signTokenCounter.Add(1)
		timer := prometheus.NewTimer(signTokenDuration)
		signedTokens[i], err = key.Sign(blindedToken)
		if err != nil {
			return []*crypto.SignedToken{}, nil, err
		}
		timer.ObserveDuration()
	}

	timer := prometheus.NewTimer(createBatchProofDuration)
	proof, err := crypto.NewBatchDLEQProof(blindedTokens, signedTokens, key)
	if err != nil {
		return []*crypto.SignedToken{}, nil, err
	}
	timer.ObserveDuration()

	timer = prometheus.NewTimer(verifyBatchProofDuration)
	ok, err := proof.Verify(blindedTokens, signedTokens, key.PublicKey())
	if err != nil {
		return []*crypto.SignedToken{}, nil, err
	}
	if !ok {
		return []*crypto.SignedToken{}, nil, ErrInvalidBatchProof
	}
	timer.ObserveDuration()

	return signedTokens, proof, err
}

// VerifyTokenRedemption checks a redemption request against the observed request data
// and MAC according a set of keys.
// Keys keeps a set of private keys that are ever used to sign the token so we can rotate private key easily.
func VerifyTokenRedemption(preimage *crypto.TokenPreimage, signature *crypto.VerificationSignature, payload string, keys []*crypto.SigningKey) error {
	if !acceptLegacyDerivation {
		// Accept only RFC 9497 HashToGroup redemptions.
		return verifyTokenRedemptionRFC(preimage, signature, payload, keys)
	}

	err := verifyTokenRedemption(preimage, signature, payload, keys)
	if err == nil || errors.Is(err, ErrIdentityPreimage) {
		return err
	}

	// Clients that derive the point with RFC 9497 HashToGroup (RFC 9380
	// hash_to_ristretto255) verify here; the derivation above serves clients
	// that derive it directly. Surface an identity-element rejection from this
	// derivation too, mirroring the legacy check above.
	rfcErr := verifyTokenRedemptionRFC(preimage, signature, payload, keys)
	if rfcErr == nil || errors.Is(rfcErr, ErrIdentityPreimage) {
		return rfcErr
	}

	return err
}

// verifyTokenRedemptionRFC verifies a redemption whose point is derived with
// RFC 9497 HashToGroup (hash_to_ristretto255) and whose verification key is the
// RFC 9497 finalization over the preimage and that point. A preimage that maps
// to the group identity element is rejected per RFC 9497 Section 3.3.1.
func verifyTokenRedemptionRFC(preimage *crypto.TokenPreimage, signature *crypto.VerificationSignature, payload string, keys []*crypto.SigningKey) error {
	var valid bool
	for i := range keys {
		verifyTokenRedemptionCounter.Add(1)

		// Rederive the unblinded token with the RFC HashToGroup point
		// derivation. This rejects a preimage that maps to the group identity.
		unblindedToken, err := keys[i].RederiveUnblindedTokenRfc(preimage)
		if err != nil {
			return ErrIdentityPreimage
		}

		timerUT := prometheus.NewTimer(verifyTokenDeriveKeyDuration)
		sharedKey := unblindedToken.DeriveVerificationKeyRfc()
		_ = timerUT.ObserveDuration()

		timerVrf := prometheus.NewTimer(verifyTokenSignatureDuration)
		ok, err := sharedKey.Verify(signature, payload)
		if err != nil {
			_ = timerVrf.ObserveDuration()
			return err
		}
		_ = timerVrf.ObserveDuration()

		if ok {
			valid = true
			break
		}
	}

	if !valid {
		return fmt.Errorf("%s, payload: %s", ErrInvalidMAC.Error(), payload)
	}
	return nil
}

func verifyTokenRedemption(preimage *crypto.TokenPreimage, signature *crypto.VerificationSignature, payload string, keys []*crypto.SigningKey) error {
	var valid bool
	var err error

	for i := range keys {
		verifyTokenRedemptionCounter.Add(1)

		// Derive the unblinded token using a server's key and the client's preimage.
		unblindedToken := keys[i].RederiveUnblindedToken(preimage)

		// Reject a preimage whose derived point is the group identity element,
		// per RFC 9497 Section 3.3.1 (InvalidInputError).
		identityDetected, idErr := isIdentityUnblindedToken(unblindedToken)
		if idErr != nil {
			return idErr
		}
		if identityDetected {
			return ErrIdentityPreimage
		}

		timerUT := prometheus.NewTimer(verifyTokenDeriveKeyDuration)

		// Derive the shared key from the unblinded token.
		sharedKey := unblindedToken.DeriveVerificationKey()
		_ = timerUT.ObserveDuration()

		timerVrf := prometheus.NewTimer(verifyTokenSignatureDuration)

		// Sign the same message using the shared key and compare the client's signature with the server's.
		valid, err = sharedKey.Verify(signature, payload)
		if err != nil {
			_ = timerVrf.ObserveDuration()

			return err
		}

		_ = timerVrf.ObserveDuration()

		if valid {
			break
		}
	}

	if !valid {
		return fmt.Errorf("%s, payload: %s", ErrInvalidMAC.Error(), payload)
	}

	return nil
}

// isIdentityUnblindedToken reports whether the rederived point W of an
// unblinded token is the ristretto identity element. The token serializes as
// base64 of preimage(64) || W(32). The identity's compressed encoding is 32
// zero bytes so W is the identity iff the trailing 32 bytes are all zero.
func isIdentityUnblindedToken(t *crypto.UnblindedToken) (bool, error) {
	text, err := t.MarshalText()
	if err != nil {
		return false, err
	}

	raw, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return false, err
	}

	const (
		preimageLen = 64
		pointLen    = 32
	)
	if len(raw) != preimageLen+pointLen {
		return false, fmt.Errorf("unexpected unblinded token length %d", len(raw))
	}

	for _, b := range raw[preimageLen:] {
		if b != 0 {
			return false, nil
		}
	}

	return true, nil
}
