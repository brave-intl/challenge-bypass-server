package ptr

import "time"

// FromString returns pointer to string
func FromString(s string) *string {
	return &s
}

// FromTime - return the pointer from a time?
func FromTime(t time.Time) *time.Time {
	return &t
}
