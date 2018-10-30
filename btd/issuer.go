package btd

import (
	"errors"
	"fmt"

	crypto "github.com/evq/challenge-bypass-ristretto-ffi"
)

var (
	ErrInvalidMAC                = errors.New("binding MAC didn't match derived MAC")
	ErrNoDoubleSpendList         = errors.New("bloom filter is not initialized")
	ErrDoubleSpend               = errors.New("token was already spent")
	ErrTooManyTokens             = errors.New("ISSUE request contained too many tokens")
	ErrTooFewRedemptionArguments = errors.New("REDEEM request did not contain enough arguments")
	ErrUnexpectedRequestType     = errors.New("unexpected request type")
	ErrInvalidBatchProof         = errors.New("New batch proof for signed tokens is invalid")
	ErrNotOnCurve                = errors.New("One or more points not found on curve")
)

// ApproveTokens applies the issuer's secret key to each token in the request.
// It returns an array of marshaled approved values along with a batch DLEQ proof.
func ApproveTokens(blindedTokens []*crypto.BlindedToken, key *crypto.SigningKey) ([]*crypto.SignedToken, *crypto.BatchDLEQProof, error) {
	var err error

	signedTokens := make([]*crypto.SignedToken, len(blindedTokens))
	for i, blindedToken := range blindedTokens {
		signedTokens[i], err = key.Sign(blindedToken)
		if err != nil {
			return []*crypto.SignedToken{}, nil, err
		}
	}

	proof, err := crypto.NewBatchDLEQProof(blindedTokens, signedTokens, key)
	if err != nil {
		return []*crypto.SignedToken{}, nil, err
	}

	ok, err := proof.Verify(blindedTokens, signedTokens, key.PublicKey())
	if err != nil {
		return []*crypto.SignedToken{}, nil, err
	}
	if !ok {
		return []*crypto.SignedToken{}, nil, ErrInvalidBatchProof
	}

	return signedTokens, proof, err
}

// VerifyTokenRedemption checks a redemption request against the observed request data
// and MAC according a set of keys. keys keeps a set of private keys that
// are ever used to sign the token so we can rotate private key easily
// Returns nil on success and an error on failure.
func VerifyTokenRedemption(preimage *crypto.TokenPreimage, signature *crypto.VerificationSignature, payload string, keys []*crypto.SigningKey) error {
	var valid bool
	var err error
	for _, key := range keys {
		// server derives the unblinded token using it's key and the clients token preimage
		unblindedToken := key.RederiveUnblindedToken(preimage)

		// server derives the shared key from the unblinded token
		sharedKey := unblindedToken.DeriveVerificationKey()

		// server signs the same message using the shared key and compares the client signature to it's own
		valid, err = sharedKey.Verify(signature, payload)
		if err != nil {
			return err
		}
		if valid {
			break
		}
	}

	if !valid {
		return fmt.Errorf("%s, payload: %s", ErrInvalidMAC.Error(), payload)
	}

	return nil
}
