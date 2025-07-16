// Package kafka manages kafka interaction
package kafka

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/assert"
)

type testMessageReader struct {
	fetch func() (kafka.Message, error)
}

func (r *testMessageReader) FetchMessage(ctx context.Context) (kafka.Message, error) {
	return r.fetch()
}

func (r *testMessageReader) Stats() kafka.ReaderStats {
	return kafka.ReaderStats{}
}

func TestProcessMessagesIntoBatchPipeline(t *testing.T) {
	nopLog := slog.New(slog.DiscardHandler)
	t.Run("AbsentTopicClosesMsg", func(t *testing.T) {
		t.Parallel()

		batchPipeline := make(chan *MessageContext)

		r := &testMessageReader{}
		messageCounter := 0
		r.fetch = func() (kafka.Message, error) {
			messageCounter++
			if messageCounter == 1 {
				return kafka.Message{Topic: "absent"}, nil
			}
			// processMessagesIntoBatchPipeline never returns, so leak its
			// goroutine via blocking here forever.
			select {}
		}
		go processMessagesIntoBatchPipeline(context.Background(),
			nil, r, batchPipeline, nopLog)
		msg := <-batchPipeline
		assert.NotNil(t, msg)
		<-msg.done
		assert.Equal(t, "absent", msg.msg.Topic)

		// Absent topic signals permanent error and the message should be
		// committed, so msg.err must be nil.
		assert.Nil(t, msg.err)
	})

	t.Run("OrderPreserved", func(t *testing.T) {
		t.Parallel()

		// The capacity of the pipeline. The code below posts double amount of
		// messages.
		N := 50
		batchPipeline := make(chan *MessageContext, N)

		r := &testMessageReader{}
		messageCounter := 0
		r.fetch = func() (kafka.Message, error) {
			i := messageCounter
			messageCounter++
			if i < 2*N {
				// processMessagesIntoBatchPipeline() does not touch
				// Message.Partition, so use that to pass message number info to
				// Processor below.
				return kafka.Message{Topic: "topicA", Partition: i}, nil
			}
			select {} // block forever
		}
		atomicCounter := int32(N)
		topicMappings := []TopicMapping{{
			Topic: "topicA",
			Processor: func(ctx context.Context, msg kafka.Message, logger *slog.Logger) error {
				if msg.Partition < N {
					// Make processor to post results in the reverse order of
					// messages using a busy wait
					for atomic.LoadInt32(&atomicCounter) != int32(msg.Partition+1) {
					}
					atomic.AddInt32(&atomicCounter, int32(-1))
				}

				if msg.Partition == 0 || msg.Partition == N {
					return errors.New("error")
				}
				return nil
			},
		}}

		go processMessagesIntoBatchPipeline(context.Background(),
			topicMappings, r, batchPipeline, nopLog)
		for i := 0; i < 2*N; i++ {
			msg := <-batchPipeline
			assert.NotNil(t, msg)
			<-msg.done
			assert.Equal(t, "topicA", msg.msg.Topic)
			assert.Equal(t, i, msg.msg.Partition)
			if i == 0 || i == N {
				assert.NotNil(t, msg.err)
			} else {
				assert.Nil(t, msg.err)
			}
		}
	})
}
