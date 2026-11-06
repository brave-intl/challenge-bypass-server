package adminapi

import (
	"testing"
	"time"

	timeutils "github.com/brave-intl/bat-go/libs/time"
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

func TestWindowsEnd(t *testing.T) {
	jan31 := time.Date(2027, 1, 31, 0, 0, 0, 0, time.UTC)
	if got, err := WindowsEnd("", 3, jan31); err != nil || !got.Equal(jan31) {
		t.Errorf("empty duration: %v %v", got, err)
	}
	if _, err := WindowsEnd("bogus", 3, jan31); err == nil {
		t.Error("bad duration must error")
	}
	// three steps of the cron's own ISO stepping, not AddDate
	d, _ := timeutils.ParseDuration("P1M")
	want := jan31
	for range 3 {
		next, _ := d.From(want)
		want = *next
	}
	if got, err := WindowsEnd("P1M", 3, jan31); err != nil || !got.Equal(want) {
		t.Errorf("P1M x 3 from Jan 31: got %v %v, want %v", got, err, want)
	}
}
