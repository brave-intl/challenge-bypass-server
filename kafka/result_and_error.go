package kafka

import (
	"github.com/brave-intl/challenge-bypass-server/utils"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
)

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
	if processingError.Temporary == true {
		return nil, processingError
	}
	return &ProcessingResult{
		Message:        []byte(message),
		ResultProducer: producer,
		RequestID:      requestID,
	}, processingError
}
