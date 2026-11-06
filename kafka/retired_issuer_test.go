package kafka

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/model"
)

func TestRetiredSigningResult(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Second), now.Add(time.Hour)
	req := avroSchema.SigningRequest{Associated_data: []byte("meta"), Blinded_tokens: []string{"t"}}

	for name, stop := range map[string]*time.Time{"not retired": nil, "retiring": &future} {
		_, retired := retiredSigningResult(&model.Issuer{StopIssuingAt: stop}, req, now)
		assert.False(t, retired, "%s: must still sign", name)
	}

	res, retired := retiredSigningResult(&model.Issuer{StopIssuingAt: &past}, req, now)
	require.True(t, retired, "past stop_issuing_at must reject")
	assert.Equal(t, avroSchema.SigningResultV2StatusInvalid_issuer, res.Status)
	assert.Nil(t, res.Signed_tokens)
	assert.Empty(t, res.Issuer_public_key)
	assert.Equal(t, "meta", string(res.Associated_data))
}
