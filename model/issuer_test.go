package model

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	should "github.com/stretchr/testify/assert"
	must "github.com/stretchr/testify/require"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
)

func TestIssuer_HasExpired(t *testing.T) {
	type tcGiven struct {
		issuer *Issuer
		now    time.Time
	}

	type testCase struct {
		name  string
		given tcGiven
		exp   bool
	}

	tests := []testCase{
		{
			name: "expires_at_zero",
			given: tcGiven{
				issuer: &Issuer{
					ID: ptrTo(uuid.MustParse("f100ded0-0000-4000-a000-000000000000")),
				},
				now: time.Date(2024, time.January, 1, 0, 0, 1, 0, time.UTC),
			},
		},

		{
			name: "expires_at_same",
			given: tcGiven{
				issuer: &Issuer{
					ID: ptrTo(uuid.MustParse("f100ded0-0000-4000-a000-000000000000")),
					ExpiresAt: pq.NullTime{
						Time:  time.Date(2024, time.January, 1, 0, 0, 1, 0, time.UTC),
						Valid: true,
					},
				},
				now: time.Date(2024, time.January, 1, 0, 0, 1, 0, time.UTC),
			},
		},

		{
			name: "expires_at_after",
			given: tcGiven{
				issuer: &Issuer{
					ID: ptrTo(uuid.MustParse("f100ded0-0000-4000-a000-000000000000")),
					ExpiresAt: pq.NullTime{
						Time:  time.Date(2024, time.January, 2, 0, 0, 1, 0, time.UTC),
						Valid: true,
					},
				},
				now: time.Date(2024, time.January, 1, 0, 0, 1, 0, time.UTC),
			},
		},

		{
			name: "expires_at_before",
			given: tcGiven{
				issuer: &Issuer{
					ID: ptrTo(uuid.MustParse("f100ded0-0000-4000-a000-000000000000")),
					ExpiresAt: pq.NullTime{
						Time:  time.Date(2023, time.December, 31, 23, 59, 59, 0, time.UTC),
						Valid: true,
					},
				},
				now: time.Date(2024, time.January, 1, 0, 0, 1, 0, time.UTC),
			},
			exp: true,
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual := tc.given.issuer.HasExpired(tc.given.now)
			should.Equal(t, tc.exp, actual)
		})
	}
}

func TestFindSigningKeys(t *testing.T) {
	type tcGiven struct {
		issuer *Issuer
		now    time.Time
	}

	type tcExpected struct {
		num int
		err error
	}

	type testCase struct {
		name  string
		given tcGiven
		exp   tcExpected
	}

	tests := []testCase{
		{
			name: "not_v3",
			given: tcGiven{
				issuer: &Issuer{Version: 2},
				now:    time.Date(2024, time.January, 1, 1, 0, 1, 0, time.UTC),
			},
			exp: tcExpected{err: ErrInvalidIssuerType},
		},

		{
			name: "invalid_key_both_times",
			given: tcGiven{
				issuer: &Issuer{
					Version: 3,
					Keys:    []IssuerKeys{{}},
				},
				now: time.Date(2024, time.January, 1, 1, 0, 1, 0, time.UTC),
			},
			exp: tcExpected{err: ErrInvalidIV3Key},
		},

		{
			name: "valid_key_inactive",
			given: tcGiven{
				issuer: &Issuer{
					Version: 3,
					Keys: []IssuerKeys{
						{
							StartAt: ptrTo(time.Date(2024, time.January, 1, 0, 0, 1, 0, time.UTC)),
							EndAt:   ptrTo(time.Date(2024, time.January, 2, 0, 0, 1, 0, time.UTC)),
						},
					},
				},
				now: time.Date(2023, time.December, 31, 0, 0, 1, 0, time.UTC),
			},
		},

		{
			name: "valid_key_active",
			given: tcGiven{
				issuer: &Issuer{
					Version: 3,
					Keys: []IssuerKeys{
						{
							SigningKey: mustRandomSigningKey(),
							StartAt:    ptrTo(time.Date(2024, time.January, 1, 0, 0, 1, 0, time.UTC)),
							EndAt:      ptrTo(time.Date(2024, time.January, 2, 0, 0, 1, 0, time.UTC)),
						},
					},
				},
				now: time.Date(2024, time.January, 1, 1, 0, 1, 0, time.UTC),
			},
			exp: tcExpected{num: 1},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual, err := tc.given.issuer.FindSigningKeys(tc.given.now)
			must.Equal(t, tc.exp.err, err)

			if tc.exp.err != nil {
				return
			}

			should.Equal(t, tc.exp.num, len(actual))
		})
	}
}

func TestIssuer_findActiveKeys(t *testing.T) {
	type tcGiven struct {
		issuer *Issuer
		now    time.Time
		lw     time.Duration
	}

	type tcExpected struct {
		result []*IssuerKeys
		err    error
	}

	type testCase struct {
		name  string
		given tcGiven
		exp   tcExpected
	}

	tests := []testCase{
		{
			name: "empty",
			given: tcGiven{
				issuer: &Issuer{},
				now:    time.Date(2024, time.January, 1, 0, 0, 1, 0, time.UTC),
			},
		},

		{
			name: "invalid_key",
			given: tcGiven{
				issuer: &Issuer{
					Version: 3,
					Keys:    []IssuerKeys{{}},
				},
				now: time.Date(2024, time.January, 1, 0, 0, 1, 0, time.UTC),
			},
			exp: tcExpected{err: ErrInvalidIV3Key},
		},

		{
			name: "valid_key_inactive",
			given: tcGiven{
				issuer: &Issuer{
					Version: 3,
					Keys: []IssuerKeys{
						{
							StartAt: ptrTo(time.Date(2024, time.January, 1, 0, 0, 1, 0, time.UTC)),
							EndAt:   ptrTo(time.Date(2024, time.January, 2, 0, 0, 1, 0, time.UTC)),
						},
					},
				},
				now: time.Date(2023, time.December, 31, 0, 0, 1, 0, time.UTC),
			},
		},

		{
			name: "valid_key_active",
			given: tcGiven{
				issuer: &Issuer{
					Version: 3,
					Keys: []IssuerKeys{
						{
							StartAt: ptrTo(time.Date(2024, time.January, 1, 0, 0, 1, 0, time.UTC)),
							EndAt:   ptrTo(time.Date(2024, time.January, 2, 0, 0, 1, 0, time.UTC)),
						},
					},
				},
				now: time.Date(2024, time.January, 1, 1, 0, 1, 0, time.UTC),
			},
			exp: tcExpected{
				result: []*IssuerKeys{
					{
						StartAt: ptrTo(time.Date(2024, time.January, 1, 0, 0, 1, 0, time.UTC)),
						EndAt:   ptrTo(time.Date(2024, time.January, 2, 0, 0, 1, 0, time.UTC)),
					},
				},
			},
		},

		{
			name: "valid_key_inactive_leeway",
			given: tcGiven{
				issuer: &Issuer{
					Version: 3,
					Keys: []IssuerKeys{
						{
							StartAt: ptrTo(time.Date(2024, time.January, 1, 0, 0, 1, 0, time.UTC)),
							EndAt:   ptrTo(time.Date(2024, time.January, 2, 0, 0, 1, 0, time.UTC)),
						},
					},
				},
				now: time.Date(2023, time.December, 31, 23, 30, 1, 0, time.UTC),
				lw:  1 * time.Hour,
			},
			exp: tcExpected{
				result: []*IssuerKeys{
					{
						StartAt: ptrTo(time.Date(2024, time.January, 1, 0, 0, 1, 0, time.UTC)),
						EndAt:   ptrTo(time.Date(2024, time.January, 2, 0, 0, 1, 0, time.UTC)),
					},
				},
			},
		},

		{
			name: "evq_strict_b_leeway_a",
			given: tcGiven{
				issuer: &Issuer{
					Version: 3,
					Keys: []IssuerKeys{
						{
							SigningKey: []byte(`key_a`),
							StartAt:    ptrTo(time.Date(2024, time.May, 23, 0, 0, 0, 0, time.UTC)),
							EndAt:      ptrTo(time.Date(2024, time.May, 24, 0, 0, 0, 0, time.UTC)),
						},

						{
							SigningKey: []byte(`key_b`),
							StartAt:    ptrTo(time.Date(2024, time.May, 24, 0, 0, 0, 0, time.UTC)),
							EndAt:      ptrTo(time.Date(2024, time.May, 25, 0, 0, 0, 0, time.UTC)),
						},

						{
							SigningKey: []byte(`key_c`),
							StartAt:    ptrTo(time.Date(2024, time.May, 25, 0, 0, 0, 0, time.UTC)),
							EndAt:      ptrTo(time.Date(2024, time.May, 26, 0, 0, 0, 0, time.UTC)),
						},
					},
				},
				now: time.Date(2024, time.May, 24, 0, 52, 25, 0, time.UTC),
				lw:  1 * time.Hour,
			},
			exp: tcExpected{
				result: []*IssuerKeys{
					{
						SigningKey: []byte(`key_b`),
						StartAt:    ptrTo(time.Date(2024, time.May, 24, 0, 0, 0, 0, time.UTC)),
						EndAt:      ptrTo(time.Date(2024, time.May, 25, 0, 0, 0, 0, time.UTC)),
					},

					{
						SigningKey: []byte(`key_a`),
						StartAt:    ptrTo(time.Date(2024, time.May, 23, 0, 0, 0, 0, time.UTC)),
						EndAt:      ptrTo(time.Date(2024, time.May, 24, 0, 0, 0, 0, time.UTC)),
					},
				},
			},
		},

		{
			name: "evq_strict_b_leeway_c",
			given: tcGiven{
				issuer: &Issuer{
					Version: 3,
					Keys: []IssuerKeys{
						{
							SigningKey: []byte(`key_a`),
							StartAt:    ptrTo(time.Date(2024, time.May, 23, 0, 0, 0, 0, time.UTC)),
							EndAt:      ptrTo(time.Date(2024, time.May, 24, 0, 0, 0, 0, time.UTC)),
						},

						{
							SigningKey: []byte(`key_b`),
							StartAt:    ptrTo(time.Date(2024, time.May, 24, 0, 0, 0, 0, time.UTC)),
							EndAt:      ptrTo(time.Date(2024, time.May, 25, 0, 0, 0, 0, time.UTC)),
						},

						{
							SigningKey: []byte(`key_c`),
							StartAt:    ptrTo(time.Date(2024, time.May, 25, 0, 0, 0, 0, time.UTC)),
							EndAt:      ptrTo(time.Date(2024, time.May, 26, 0, 0, 0, 0, time.UTC)),
						},
					},
				},
				now: time.Date(2024, time.May, 24, 23, 52, 25, 0, time.UTC),
				lw:  1 * time.Hour,
			},
			exp: tcExpected{
				result: []*IssuerKeys{
					{
						SigningKey: []byte(`key_b`),
						StartAt:    ptrTo(time.Date(2024, time.May, 24, 0, 0, 0, 0, time.UTC)),
						EndAt:      ptrTo(time.Date(2024, time.May, 25, 0, 0, 0, 0, time.UTC)),
					},

					{
						SigningKey: []byte(`key_c`),
						StartAt:    ptrTo(time.Date(2024, time.May, 25, 0, 0, 0, 0, time.UTC)),
						EndAt:      ptrTo(time.Date(2024, time.May, 26, 0, 0, 0, 0, time.UTC)),
					},
				},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual, err := tc.given.issuer.findActiveKeys(tc.given.now, tc.given.lw)
			must.Equal(t, tc.exp.err, err)

			if tc.exp.err != nil {
				return
			}

			should.Equal(t, tc.exp.result, actual)
		})
	}
}

func ptrTo[T any](v T) *T {
	return &v
}

func mustRandomSigningKey() []byte {
	key, err := crypto.RandomSigningKey()
	if err != nil {
		panic(err)
	}

	data, err := key.MarshalText()
	if err != nil {
		panic(err)
	}

	return data
}
