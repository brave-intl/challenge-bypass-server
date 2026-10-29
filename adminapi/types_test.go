package adminapi

import (
	"testing"
	"time"
)

func TestMinStopRedeeming(t *testing.T) {
	cases := map[string]string{
		"2027-02-01": "2027-05-02", // 3 months is 89 days: 90 days wins
		"2027-11-01": "2028-02-01", // 3 months is 92 days: 3 months wins
	}
	for in, want := range cases {
		from, _ := time.Parse("2006-01-02", in)
		w, _ := time.Parse("2006-01-02", want)
		if got := MinStopRedeeming(from); !got.Equal(w) {
			t.Errorf("%s: got %s want %s", in, got, w)
		}
	}
}
