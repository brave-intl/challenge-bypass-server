package btd

import (
	"errors"
	"fmt"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// ErrInvalidMAC - the mac was invalid
	ErrInvalidMAC = errors.New("binding MAC didn't match derived MAC")
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
	var valid bool
	var err error

	for i := range keys {
		verifyTokenRedemptionCounter.Add(1)

		// Derive the unblinded token using a server's key and the client's preimage.
		unblindedToken := keys[i].RederiveUnblindedToken(preimage)

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
