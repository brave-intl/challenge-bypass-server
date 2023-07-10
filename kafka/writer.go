package kafka

import (
	"context"

	"github.com/segmentio/kafka-go"
)

type Writer interface {
	WriteMessages(context.Context, ...kafka.Message) error
	Topic() string
}

type KafkaWriter struct {
	*kafka.Writer
}

func (w *KafkaWriter) Topic() string {
	return w.Writer.Topic
}

func NewWriter(c kafka.WriterConfig) Writer {
	w := kafka.NewWriter(c)
	return &KafkaWriter{w}
}
