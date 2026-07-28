package btd

import (
	"encoding/base64"
	"errors"
	"log"
	"testing"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
)

var testPayload = "Some test payload"

// Generates a small but well-formed ISSUE request for testing.
func makeTokenIssueRequest() ([]*crypto.Token, []*crypto.BlindedToken, error) {
	tokens := make([]*crypto.Token, 10)
	blindedTokens := make([]*crypto.BlindedToken, 10)
	for i := 0; i < len(tokens); i++ {
		token, err := crypto.RandomToken()
		if err != nil {
			return nil, nil, err
		}
		tokens[i] = token
		blindedTokens[i] = token.Blind()
	}

	return tokens, blindedTokens, nil
}

func makeTokenRedempRequest(sKey *crypto.SigningKey) (*crypto.TokenPreimage, *crypto.VerificationSignature, error) {
	// Client
	tokens, blindedTokens, err := makeTokenIssueRequest()
	if err != nil {
		return nil, nil, err
	}

	// Client -> (request) -> Server

	// Server
	// Sign the blind points
	signedTokens, dleqProof, err := ApproveTokens(blindedTokens, sKey)
	if err != nil {
		return nil, nil, err
	}

	// Client <- (signed blind tokens) <- Server

	// Verify DLEQ proof

	pKey := sKey.PublicKey()
	clientUnblindedTokens, err := dleqProof.VerifyAndUnblind(tokens, blindedTokens, signedTokens, pKey)
	if err != nil {
		return nil, nil, err
	}

	clientUnblindedToken := clientUnblindedTokens[0]

	// Redemption

	// client derives the shared key from the unblinded token
	clientvKey := clientUnblindedToken.DeriveVerificationKey()

	// client signs a message using the shared key
	clientSig, err := clientvKey.Sign(testPayload)
	if err != nil {
		return nil, nil, err
	}
	preimage := clientUnblindedToken.Preimage()

	return preimage, clientSig, nil
}

func TestTokenIssuance(t *testing.T) {
	_, blindedTokens, err := makeTokenIssueRequest()
	if err != nil {
		t.Fatalf("it's all borked")
	}

	sKey, err := crypto.RandomSigningKey()
	if err != nil {
		log.Fatalln(err)
		t.Fatal("couldn't generate the signing key")
	}
	pKey := sKey.PublicKey()

	signedTokens, dleqProof, err := ApproveTokens(blindedTokens, sKey)
	if err != nil {
		t.Fatal(err)
	}

	// Verify DLEQ proof

	proofVerfied, err := dleqProof.Verify(blindedTokens, signedTokens, pKey)
	if err != nil {
		t.Fatal(err)
	}
	if !proofVerfied {
		t.Fatal("DLEQ proof failed to verify")
	}
}

// Tests token redemption for multiple keys
func TestTokenRedemption(t *testing.T) {
	sKey1, err := crypto.RandomSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	sKey2, err := crypto.RandomSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	sKey3, err := crypto.RandomSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	// Redemption requests for all three keys
	preimage1, sig1, err := makeTokenRedempRequest(sKey1)
	if err != nil {
		t.Fatal(err)
	}
	preimage2, sig2, err := makeTokenRedempRequest(sKey2)
	if err != nil {
		t.Fatal(err)
	}
	preimage3, sig3, err := makeTokenRedempRequest(sKey3)
	if err != nil {
		t.Fatal(err)
	}

	// Only add two keys to check that the third redemption fails
	redeemKeys := []*crypto.SigningKey{sKey1, sKey2}

	// Server
	// Check valid token redemption
	err = VerifyTokenRedemption(preimage1, sig1, testPayload, redeemKeys)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyTokenRedemption(preimage2, sig2, testPayload, redeemKeys)
	if err != nil {
		t.Fatal(err)
	}
	// Check failed redemption
	err = VerifyTokenRedemption(preimage3, sig3, testPayload, redeemKeys)
	if err == nil {
		t.Fatal("This redemption should not be verified correctly.")
	}
}

// TestIdentityPreimageRejected is a regression test for the identity
// preimage bug: a preimage that hashes to the group identity makes the
// rederived point (and thus the derived MAC key) a constant independent of the
// signing key.
func TestIdentityPreimageRejected(t *testing.T) {
	sKey, err := crypto.RandomSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	const payload = "redeem: 1 BAT reward token"

	// Identity preimage: 64 zero bytes hash to the ristretto identity.
	preimageB64 := base64.StdEncoding.EncodeToString(make([]byte, 64))
	preimage := &crypto.TokenPreimage{}
	if err := preimage.UnmarshalText([]byte(preimageB64)); err != nil {
		t.Fatal(err)
	}

	// Identity unblinded token: preimage(64) || W(32), with W set to the
	// identity's all-zero compressed encoding.
	identityUnblindedB64 := base64.StdEncoding.EncodeToString(make([]byte, 96))
	f := &crypto.UnblindedToken{}
	if err := f.UnmarshalText([]byte(identityUnblindedB64)); err != nil {
		t.Fatal(err)
	}

	fSig, err := f.DeriveVerificationKey().Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Sanity check the token is well-formed: without the guard the MAC
	// matches the server's rederived key, so this is not merely a bad MAC.
	if identity, err := isIdentityUnblindedToken(sKey.RederiveUnblindedToken(preimage)); err != nil {
		t.Fatal(err)
	} else if !identity {
		t.Fatal("expected the rederived token to be the identity")
	}

	err = VerifyTokenRedemption(preimage, fSig, payload, []*crypto.SigningKey{sKey})
	if !errors.Is(err, ErrIdentityPreimage) {
		t.Fatalf("identity-preimage token must be rejected with ErrIdentityPreimage, got: %v", err)
	}

	// Key independence: a second, unrelated key must reject it the same way.
	sKey2, err := crypto.RandomSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTokenRedemption(preimage, fSig, payload, []*crypto.SigningKey{sKey2}); !errors.Is(err, ErrIdentityPreimage) {
		t.Fatalf("identity-preimage token must be rejected for any key, got: %v", err)
	}
}

func TestBadMAC(t *testing.T) {
	sKey, err := crypto.RandomSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	preimage, sig, err := makeTokenRedempRequest(sKey)
	if err != nil {
		t.Fatal(err)
	}

	// Server
	// Check bad token redemption
	err = VerifyTokenRedemption(preimage, sig, "bad payload", []*crypto.SigningKey{sKey})
	if err == nil {
		t.Fatal("No error occurred even though MAC should be bad")
	}
}

// makeTokenRedempRequestRFC builds a redemption whose verification key is
// derived with the RFC 9497 HashToGroup path, matching how an RFC client
// redeems. The RFC unblinded point W = k * hash_to_ristretto255(preimage) is a
// deterministic function of the signing key and preimage, so rederiving it with
// the RFC method reproduces exactly the client's token; the shared key is then
// the RFC 9497 finalization over the preimage and that point.
func makeTokenRedempRequestRFC(sKey *crypto.SigningKey) (*crypto.TokenPreimage, *crypto.VerificationSignature, error) {
	// Obtain a genuine token preimage via the normal issuance flow.
	tokens, blindedTokens, err := makeTokenIssueRequest()
	if err != nil {
		return nil, nil, err
	}
	signedTokens, dleqProof, err := ApproveTokens(blindedTokens, sKey)
	if err != nil {
		return nil, nil, err
	}
	clientUnblindedTokens, err := dleqProof.VerifyAndUnblind(tokens, blindedTokens, signedTokens, sKey.PublicKey())
	if err != nil {
		return nil, nil, err
	}
	preimage := clientUnblindedTokens[0].Preimage()

	rfcToken, err := sKey.RederiveUnblindedTokenRfc(preimage)
	if err != nil {
		return nil, nil, err
	}
	sig, err := rfcToken.DeriveVerificationKeyRfc().Sign(testPayload)
	if err != nil {
		return nil, nil, err
	}
	return preimage, sig, nil
}

// TestTokenRedemptionRFC exercises the RFC 9497 HashToGroup redemption path end
// to end: a redemption whose verification key uses the RFC derivation is
// accepted through VerifyTokenRedemption's dual-accept fallback, while a wrong
// payload or a key that never signed the token is rejected.
func TestTokenRedemptionRFC(t *testing.T) {
	sKey1, err := crypto.RandomSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	sKey2, err := crypto.RandomSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	preimage, sig, err := makeTokenRedempRequestRFC(sKey1)
	if err != nil {
		t.Fatal(err)
	}

	// A valid RFC redemption verifies even with an extra key present.
	if err := VerifyTokenRedemption(preimage, sig, testPayload, []*crypto.SigningKey{sKey1, sKey2}); err != nil {
		t.Fatalf("valid RFC redemption should verify: %v", err)
	}

	// The wrong payload is rejected.
	if err := VerifyTokenRedemption(preimage, sig, "bad payload", []*crypto.SigningKey{sKey1}); err == nil {
		t.Fatal("RFC redemption with wrong payload must not verify")
	}

	// A key that never signed the token is rejected.
	if err := VerifyTokenRedemption(preimage, sig, testPayload, []*crypto.SigningKey{sKey2}); err == nil {
		t.Fatal("RFC redemption must not verify under a non-redeeming key")
	}
}

// TestLegacyDerivationDisabled checks that when ACCEPT_LEGACY_TOKENS is off, a
// legacy redemption is rejected while an RFC 9497 redemption still verifies.
func TestLegacyDerivationDisabled(t *testing.T) {
	prev := acceptLegacyDerivation
	acceptLegacyDerivation = false
	defer func() { acceptLegacyDerivation = prev }()

	sKey, err := crypto.RandomSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	legacyPreimage, legacySig, err := makeTokenRedempRequest(sKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTokenRedemption(legacyPreimage, legacySig, testPayload, []*crypto.SigningKey{sKey}); err == nil {
		t.Fatal("legacy redemption must be rejected when legacy derivation is disabled")
	}

	rfcPreimage, rfcSig, err := makeTokenRedempRequestRFC(sKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTokenRedemption(rfcPreimage, rfcSig, testPayload, []*crypto.SigningKey{sKey}); err != nil {
		t.Fatalf("RFC redemption must still verify when legacy derivation is disabled: %v", err)
	}
}

// TestTokenRedemptionWrongDerivationRejected is a full end-to-end test showing
// that a verification key built from the wrong derivation path fails validation
// under BOTH server verification methods (RFC and legacy), and is therefore
// rejected by VerifyTokenRedemption. The token's unblinded point is derived
// with the RFC 9497 HashToGroup path; deriving its verification key with the
// legacy finalization instead yields a signature that pairs with neither
// method: the RFC method uses a different finalization, and the legacy method
// rederives a different unblinded point.
func TestTokenRedemptionWrongDerivationRejected(t *testing.T) {
	sKey, err := crypto.RandomSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	// Issue and unblind a token to obtain a genuine preimage.
	tokens, blindedTokens, err := makeTokenIssueRequest()
	if err != nil {
		t.Fatal(err)
	}
	signedTokens, dleqProof, err := ApproveTokens(blindedTokens, sKey)
	if err != nil {
		t.Fatal(err)
	}
	clientUnblindedTokens, err := dleqProof.VerifyAndUnblind(tokens, blindedTokens, signedTokens, sKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	preimage := clientUnblindedTokens[0].Preimage()

	// The RFC unblinded point W = k * hash_to_ristretto255(preimage).
	rfcToken, err := sKey.RederiveUnblindedTokenRfc(preimage)
	if err != nil {
		t.Fatal(err)
	}

	keys := []*crypto.SigningKey{sKey}

	// Sanity: the correctly derived RFC verification key verifies, so any
	// rejection below is due to the derivation mismatch, not a bad token.
	correctSig, err := rfcToken.DeriveVerificationKeyRfc().Sign(testPayload)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyTokenRedemptionRFC(preimage, correctSig, testPayload, keys); err != nil {
		t.Fatalf("sanity: correctly derived RFC key should verify: %v", err)
	}
	// The same token verifies through the dual-accept entry point when its
	// verification key is generated correctly.
	if err := VerifyTokenRedemption(preimage, correctSig, testPayload, keys); err != nil {
		t.Fatalf("same token with a correctly derived key must verify: %v", err)
	}

	// Wrong derivation: the RFC token, but with its verification key derived
	// using the legacy finalization.
	wrongSig, err := rfcToken.DeriveVerificationKey().Sign(testPayload)
	if err != nil {
		t.Fatal(err)
	}

	// It verifies under neither server method.
	if err := verifyTokenRedemptionRFC(preimage, wrongSig, testPayload, keys); err == nil {
		t.Fatal("RFC verification must reject a wrong-derivation verification key")
	}
	if err := verifyTokenRedemption(preimage, wrongSig, testPayload, keys); err == nil {
		t.Fatal("legacy verification must reject a wrong-derivation verification key")
	}

	// And the dual-accept entry point, which tries both, rejects it.
	if err := VerifyTokenRedemption(preimage, wrongSig, testPayload, keys); err == nil {
		t.Fatal("VerifyTokenRedemption must reject a wrong-derivation verification key")
	}
}

// TestTokenRedemptionWrongDerivationRejectedLegacy is the legacy counterpart of
// TestTokenRedemptionWrongDerivationRejected: a token blinded and unblinded with
// the legacy derivation verifies when its verification key uses the legacy
// finalization, and is rejected under BOTH server methods when the key is built
// with the RFC 9497 finalization instead.
func TestTokenRedemptionWrongDerivationRejectedLegacy(t *testing.T) {
	sKey, err := crypto.RandomSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	// Issue and unblind a token; the FFI blinds with the legacy derivation, so
	// this client unblinded token's point is W = k * from_uniform_bytes(preimage).
	tokens, blindedTokens, err := makeTokenIssueRequest()
	if err != nil {
		t.Fatal(err)
	}
	signedTokens, dleqProof, err := ApproveTokens(blindedTokens, sKey)
	if err != nil {
		t.Fatal(err)
	}
	clientUnblindedTokens, err := dleqProof.VerifyAndUnblind(tokens, blindedTokens, signedTokens, sKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	clientUnblindedToken := clientUnblindedTokens[0]
	preimage := clientUnblindedToken.Preimage()

	keys := []*crypto.SigningKey{sKey}

	// Correct derivation (legacy finalization) verifies, including through the
	// dual-accept entry point.
	correctSig, err := clientUnblindedToken.DeriveVerificationKey().Sign(testPayload)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyTokenRedemption(preimage, correctSig, testPayload, keys); err != nil {
		t.Fatalf("sanity: correctly derived legacy key should verify: %v", err)
	}
	if err := VerifyTokenRedemption(preimage, correctSig, testPayload, keys); err != nil {
		t.Fatalf("same token with a correctly derived key must verify: %v", err)
	}

	// Wrong derivation: the legacy token, but with its verification key derived
	// using the RFC 9497 finalization.
	wrongSig, err := clientUnblindedToken.DeriveVerificationKeyRfc().Sign(testPayload)
	if err != nil {
		t.Fatal(err)
	}

	// It verifies under neither server method.
	if err := verifyTokenRedemption(preimage, wrongSig, testPayload, keys); err == nil {
		t.Fatal("legacy verification must reject a wrong-derivation verification key")
	}
	if err := verifyTokenRedemptionRFC(preimage, wrongSig, testPayload, keys); err == nil {
		t.Fatal("RFC verification must reject a wrong-derivation verification key")
	}

	// And the dual-accept entry point, which tries both, rejects it.
	if err := VerifyTokenRedemption(preimage, wrongSig, testPayload, keys); err == nil {
		t.Fatal("VerifyTokenRedemption must reject a wrong-derivation verification key")
	}
}
