package kafka

import (
	"context"

	"github.com/segmentio/kafka-go"
)

type Reader interface {
	CommitMessages(context.Context, ...kafka.Message) error
	FetchMessage(context.Context) (kafka.Message, error)
	Stats() kafka.ReaderStats
}

type MessageReader struct {
	*kafka.Reader
}

func NewReader(c kafka.ReaderConfig) Reader {
	r := kafka.NewReader(c)
	return &MessageReader{r}
}
