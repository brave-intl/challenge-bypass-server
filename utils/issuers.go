package utils

import (
	"fmt"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	cbpServer "github.com/brave-intl/challenge-bypass-server/server"
	"time"
)

type SignedIssuerToken struct {
	Issuer     cbpServer.Issuer
	SigningKey *crypto.SigningKey
}

func MarshalIssuersAndSigningKeys(issuers []cbpServer.Issuer) (map[string]SignedIssuerToken, error) {
	// Create a lookup for issuers & signing keys based on public key
	signedTokens := make(map[string]SignedIssuerToken)
	for _, issuer := range issuers {
		if !issuer.ExpiresAt.IsZero() && issuer.ExpiresAt.Before(time.Now()) {
			continue
		}

		for _, issuerKey := range issuer.Keys {
			// Don't use keys outside their start/end dates
			if issuerTimeIsNotValid(issuerKey.StartAt, issuerKey.EndAt) {
				continue
			}

			signingKey := issuerKey.SigningKey
			issuerPublicKey := signingKey.PublicKey()
			marshaledPublicKey, mErr := issuerPublicKey.MarshalText()
			// Unmarshalling failure is a data issue and is probably permanent.
			if mErr != nil {
				return nil, fmt.Errorf("could not unmarshal issuer public key into text: %e", mErr)
			}

			signedTokens[string(marshaledPublicKey)] = SignedIssuerToken{
				Issuer:     issuer,
				SigningKey: signingKey,
			}
		}
	}

	return signedTokens, nil
}

func issuerTimeIsNotValid(start *time.Time, end *time.Time) bool {
	if start != nil && end != nil {
		now := time.Now()

		startIsNotZeroAndAfterNow := !start.IsZero() && start.After(now)
		endIsNotZeroAndBeforeNow := !end.IsZero() && end.Before(now)

		return startIsNotZeroAndAfterNow || endIsNotZeroAndBeforeNow
	}

	// Both times being nil is valid
	bothTimesAreNil := start == nil && end == nil
	return !bothTimesAreNil
}
