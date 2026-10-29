package kafka

import (
	"testing"
	"time"

	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/model"
)

func TestRetiredSigningResult(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Second), now.Add(time.Hour)
	req := avroSchema.SigningRequest{Associated_data: []byte("meta"), Blinded_tokens: []string{"t"}}

	for name, stop := range map[string]*time.Time{"not retired": nil, "retiring": &future} {
		if _, retired := retiredSigningResult(&model.Issuer{StopIssuingAt: stop}, req, now); retired {
			t.Errorf("%s: must still sign", name)
		}
	}

	res, retired := retiredSigningResult(&model.Issuer{StopIssuingAt: &past}, req, now)
	if !retired {
		t.Fatal("past stop_issuing_at must reject")
	}
	if res.Status != avroSchema.SigningResultV2StatusInvalid_issuer || res.Signed_tokens != nil ||
		res.Issuer_public_key != "" || string(res.Associated_data) != "meta" {
		t.Fatalf("unexpected result: %+v", res)
	}
}
