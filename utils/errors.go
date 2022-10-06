package utils

import (
	"fmt"
	"time"

	"github.com/segmentio/kafka-go"
)

// ProcessingError is an error used for Kafka processing that communicates retry data for
// failures.
type ProcessingError struct {
	OriginalError  error
	FailureMessage string
	Temporary      bool
	Backoff        time.Duration
	KafkaMessage   kafka.Message
}

// Error makes ProcessingError an error
func (e ProcessingError) Error() string {
	msg := fmt.Sprintf("error: %s", e.FailureMessage)
	if e.Cause() != nil {
		msg = fmt.Sprintf("%s: %s", msg, e.Cause())
	}
	return msg
}

// Cause implements Cause for error
func (e ProcessingError) Cause() error {
	return e.OriginalError
}
