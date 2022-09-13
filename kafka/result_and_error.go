package kafka

import (
	"github.com/brave-intl/challenge-bypass-server/utils"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
)

// ResultAndErrorFromError conditionally returns a result that can be emitted to Kafka and
// always returns a processing error.
func ResultAndErrorFromError(
	err error,
	msg kafka.Message,
	errorMessage string,
	message []byte,
	producer *kafka.Writer,
	requestID string,
	log *zerolog.Logger,
) (*ProcessingResult, *utils.ProcessingError) {
	processingError := utils.ProcessingErrorFromErrorWithMessage(err, errorMessage, msg, log)
	if processingError.Temporary {
		return nil, processingError
	}
	return &ProcessingResult{
		Message:        []byte(message),
		ResultProducer: producer,
		RequestID:      requestID,
	}, processingError
}
