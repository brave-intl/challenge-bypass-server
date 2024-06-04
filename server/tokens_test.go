package server

import (
	"testing"

	should "github.com/stretchr/testify/assert"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
)

func TestBlindedTokenRedeemRequest_isEmpty(t *testing.T) {
	tests := []struct {
		name  string
		given *blindedTokenRedeemRequest
		exp   bool
	}{
		{
			name: "no_token_preimage",
			given: &blindedTokenRedeemRequest{
				Signature: &crypto.VerificationSignature{},
			},
			exp: true,
		},

		{
			name: "no_signature",
			given: &blindedTokenRedeemRequest{
				TokenPreimage: &crypto.TokenPreimage{},
			},
			exp: true,
		},

		{
			name:  "no_token_preimage_no_signature",
			given: &blindedTokenRedeemRequest{},
			exp:   true,
		},

		{
			name: "valid",
			given: &blindedTokenRedeemRequest{
				TokenPreimage: &crypto.TokenPreimage{},
				Signature:     &crypto.VerificationSignature{},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual := tc.given.isEmpty()
			should.Equal(t, tc.exp, actual)
		})
	}
}
