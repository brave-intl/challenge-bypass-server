package utils

import (
	"fmt"

	"time"

	awsDynamoTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/rs/zerolog"
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

func ProcessingErrorFromErrorWithMessage(
	err error,
	message string,
	kafkaMessage kafka.Message,
	logger *zerolog.Logger,
) *ProcessingError {
	temporary, backoff := ErrorIsTemporary(err, logger)
	return &ProcessingError{
		OriginalError:  err,
		FailureMessage: message,
		Temporary:      temporary,
		Backoff:        backoff,
		KafkaMessage:   kafka.Message{},
	}
}

// ErrorIsTemporary takes an error and determines if it is temporary based on a set of
// known errors
func ErrorIsTemporary(err error, logger *zerolog.Logger) (bool, time.Duration) {
	var ok bool
	err, ok = err.(*awsDynamoTypes.ProvisionedThroughputExceededException)
	if ok {
		logger.Error().Err(err).Msg("Temporary message processing failure")
		return true, 1 * time.Minute
	}
	err, ok = err.(*awsDynamoTypes.RequestLimitExceeded)
	if ok {
		logger.Error().Err(err).Msg("Temporary message processing failure")
		return true, 1 * time.Minute
	}
	err, ok = err.(*awsDynamoTypes.InternalServerError)
	if ok {
		logger.Error().Err(err).Msg("Temporary message processing failure")
		return true, 1 * time.Minute
	}

	return false, 1 * time.Millisecond
}
