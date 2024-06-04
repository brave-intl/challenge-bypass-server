package model

import (
	"testing"
	"time"

	should "github.com/stretchr/testify/assert"
	must "github.com/stretchr/testify/require"
)

func TestIssuerKeys_isActiveV3(t *testing.T) {
	type tcGiven struct {
		key *IssuerKeys
		now time.Time
		lw  time.Duration
	}

	type tcExpected struct {
		val bool
		err error
	}

	type testCase struct {
		name  string
		given tcGiven
		exp   tcExpected
	}

	tests := []testCase{
		{
			name: "invalid_v3",
			given: tcGiven{
				key: &IssuerKeys{},
				now: time.Date(2024, time.January, 1, 0, 0, 1, 0, time.UTC),
				lw:  1 * time.Hour,
			},
			exp: tcExpected{err: ErrInvalidIV3Key},
		},

		{
			name: "zero_leeway",
			given: tcGiven{
				key: &IssuerKeys{
					StartAt: ptrTo(time.Date(2023, time.December, 31, 0, 0, 1, 0, time.UTC)),
					EndAt:   ptrTo(time.Date(2024, time.January, 2, 0, 0, 1, 0, time.UTC)),
				},
				now: time.Date(2024, time.January, 1, 0, 0, 1, 0, time.UTC),
			},
			exp: tcExpected{val: true},
		},

		{
			name: "leeway_1hour",
			given: tcGiven{
				key: &IssuerKeys{
					StartAt: ptrTo(time.Date(2023, time.December, 31, 0, 0, 1, 0, time.UTC)),
					EndAt:   ptrTo(time.Date(2024, time.January, 2, 0, 0, 1, 0, time.UTC)),
				},
				now: time.Date(2024, time.January, 2, 0, 0, 1, 0, time.UTC),
				lw:  1 * time.Hour,
			},
			exp: tcExpected{val: true},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual, err := tc.given.key.isActiveV3(tc.given.now, tc.given.lw)
			must.Equal(t, tc.exp.err, err)

			should.Equal(t, tc.exp.val, actual)
		})
	}
}

func TestIssuerKeys_isValidV3(t *testing.T) {
	type testCase struct {
		name  string
		given *IssuerKeys
		exp   bool
	}

	tests := []testCase{
		{
			name:  "invalid_both",
			given: &IssuerKeys{},
		},

		{
			name: "invalid_end",
			given: &IssuerKeys{
				StartAt: ptrTo(time.Date(2023, time.December, 31, 0, 0, 1, 0, time.UTC)),
			},
		},

		{
			name: "invalid_start",
			given: &IssuerKeys{
				EndAt: ptrTo(time.Date(2024, time.January, 2, 0, 0, 1, 0, time.UTC)),
			},
		},

		{
			name: "valid",
			given: &IssuerKeys{
				StartAt: ptrTo(time.Date(2023, time.December, 31, 0, 0, 1, 0, time.UTC)),
				EndAt:   ptrTo(time.Date(2024, time.January, 2, 0, 0, 1, 0, time.UTC)),
			},
			exp: true,
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual := tc.given.isValidV3()
			should.Equal(t, tc.exp, actual)
		})
	}
}

func TestIsTimeWithin(t *testing.T) {
	type tcGiven struct {
		start time.Time
		end   time.Time
		now   time.Time
	}

	type testCase struct {
		name  string
		given tcGiven
		exp   bool
	}

	tests := []testCase{
		{
			name:  "zero_all",
			given: tcGiven{},
		},

		{
			name: "zero_start_end",
			given: tcGiven{
				now: time.Date(2024, time.January, 1, 0, 0, 1, 0, time.UTC),
			},
		},

		{
			name: "zero_start_now",
			given: tcGiven{
				end: time.Date(2024, time.January, 2, 0, 0, 1, 0, time.UTC),
			},
		},

		{
			name: "zero_now_end",
			given: tcGiven{
				start: time.Date(2023, time.December, 31, 0, 0, 1, 0, time.UTC),
			},
		},

		{
			name: "zero_now",
			given: tcGiven{
				start: time.Date(2023, time.December, 31, 0, 0, 1, 0, time.UTC),
				end:   time.Date(2024, time.January, 2, 0, 0, 1, 0, time.UTC),
			},
		},

		{
			name: "invalid_inverse",
			given: tcGiven{
				start: time.Date(2024, time.January, 2, 0, 0, 1, 0, time.UTC),
				end:   time.Date(2023, time.December, 31, 0, 0, 1, 0, time.UTC),
				now:   time.Date(2024, time.January, 1, 0, 0, 1, 0, time.UTC),
			},
		},

		{
			name: "valid",
			given: tcGiven{
				start: time.Date(2023, time.December, 31, 0, 0, 1, 0, time.UTC),
				end:   time.Date(2024, time.January, 2, 0, 0, 1, 0, time.UTC),
				now:   time.Date(2024, time.January, 1, 0, 0, 1, 0, time.UTC),
			},
			exp: true,
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual := isTimeWithin(tc.given.start, tc.given.end, tc.given.now)
			should.Equal(t, tc.exp, actual)
		})
	}
}
