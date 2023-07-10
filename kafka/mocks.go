package kafka

import (
	"context"

	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/mock"
)

type MockKafkaReader struct {
	mock.Mock
}

func (m *MockKafkaReader) CommitMessages(a context.Context, b ...kafka.Message) error {
	ret := m.Called(a, b)
	return ret.Error(0)
}

func (m *MockKafkaReader) FetchMessage(a context.Context) (kafka.Message, error) {
	ret := m.Called(a)
	return ret.Get(0).(kafka.Message), ret.Error(1)
}

func (m *MockKafkaReader) Stats() kafka.ReaderStats {
	ret := m.Called()
	return ret.Get(0).(kafka.ReaderStats)
}

type MockKafkaWriter struct {
	mock.Mock
}

func (m *MockKafkaWriter) WriteMessages(a context.Context, b ...kafka.Message) error {
	ret := m.Called(a, b)
	return ret.Error(0)
}

func (m *MockKafkaWriter) Topic() string {
	ret := m.Called()
	return ret.String(0)
}
