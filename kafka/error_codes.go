package kafka

const (
	// Error types that determine commit or retry for a given offset
	PERMANENT = 0
	TEMPORARY = 1
	// Error types that determine which error response is includeded in the emission to
	// Kafka for a given request failure.
	OK                   = 0
	DUPLICATE_REDEMPTION = 1
	UNVERIFIED           = 2
	ERROR                = 3
)
