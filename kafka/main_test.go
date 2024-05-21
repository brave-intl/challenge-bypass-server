// Package kafka manages kafka interaction
package kafka

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"

	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/assert"
)

type testMessageReader struct {
	fetch  func() (kafka.Message, error)
	commit func(msgs []kafka.Message) error
}

func (r *testMessageReader) FetchMessage(ctx context.Context) (kafka.Message, error) {
	return r.fetch()
}

func (r *testMessageReader) Stats() kafka.ReaderStats {
	return kafka.ReaderStats{}
}

func (r *testMessageReader) CommitMessages(ctx context.Context, msgs ...kafka.Message) error {
	return r.commit(msgs)
}

func TestProcessMessagesIntoBatchPipeline(t *testing.T) {
	nopLog := zerolog.Nop()
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
			return kafka.Message{}, io.EOF
		}
		go processMessagesIntoBatchPipeline(context.Background(),
			nil, r, batchPipeline, &nopLog)
		msg := <-batchPipeline
		assert.NotNil(t, msg)
		<-msg.done
		assert.Equal(t, "absent", msg.msg.Topic)

		// Absent topic signals permanent error and the message should be
		// committed, so msg.err must be nil.
		assert.Nil(t, msg.err)

		_, ok := <-batchPipeline
		assert.False(t, ok)
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
			return kafka.Message{}, io.EOF
		}
		atomicCounter := int32(N)
		topicMappings := []TopicMapping{{
			Topic: "topicA",
			Processor: func(ctx context.Context, msg kafka.Message, logger *zerolog.Logger) error {
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
			topicMappings, r, batchPipeline, &nopLog)
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
		_, ok := <-batchPipeline
		assert.False(t, ok)
	})

	t.Run("ContextCancelStops", func(t *testing.T) {
		t.Parallel()

		// generate two messages and cancel context when returning the second.

		ctx, cancel := context.WithCancel(context.Background())

		batchPipeline := make(chan *MessageContext)

		r := &testMessageReader{}
		messageCounter := 0
		r.fetch = func() (kafka.Message, error) {
			i := messageCounter
			messageCounter++
			if i > 1 {
				panic("called more than once")
			}
			if i == 1 {
				cancel()
			}
			return kafka.Message{Topic: "topicA", Partition: i}, nil
		}

		topicMappings := []TopicMapping{{
			Topic: "topicA",
			Processor: func(ctx context.Context, msg kafka.Message, logger *zerolog.Logger) error {
				if msg.Partition > 0 {
					panic("should only be called once")
				}
				return nil
			},
		}}

		processFinished := make(chan struct{})
		go func() {
			processMessagesIntoBatchPipeline(ctx,
				topicMappings, r, batchPipeline, &nopLog)
			close(processFinished)
		}()

		msg := <-batchPipeline
		assert.NotNil(t, msg)
		<-msg.done

		<-processFinished

		// After processMessagesIntoBatchPipeline
		assert.Error(t, ctx.Err())
		_, ok := <-batchPipeline
		assert.False(t, ok)
	})
}

func TestReadAndCommitBatchPipelineResults(t *testing.T) {
	nopLog := zerolog.Nop()

	t.Run("WaitsForMessageDoneAfterReceiving", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		r := &testMessageReader{}

		r.commit = func(msgs []kafka.Message) error {
			assert.Equal(t, 1, len(msgs))
			assert.Equal(t, "testA", msgs[0].Topic)
			return nil
		}

		batchPipeline := make(chan *MessageContext)

		readErr := make(chan error)
		go func() {
			readErr <- readAndCommitBatchPipelineResults(ctx, r, batchPipeline, &nopLog)
		}()

		makeMsg := func() *MessageContext {
			return &MessageContext{
				msg:  kafka.Message{Topic: "testA"},
				done: make(chan struct{}),
			}
		}

		msg := makeMsg()
		batchPipeline <- msg

		// Do not close, but write an empty struct to trigger deadlock if the
		// read happens in the wrong order. For this to work all channels must
		// be unbuffered.
		var empty struct{}
		msg.done <- empty

		msg = makeMsg()
		batchPipeline <- msg
		msg.done <- empty

		msg = makeMsg()
		batchPipeline <- msg
		msg.done <- empty

		close(batchPipeline)

		err := <-readErr
		assert.ErrorIs(t, err, io.EOF)
	})

	t.Run("MessageWithErrorStopsReading", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		r := &testMessageReader{}
		r.commit = func(msgs []kafka.Message) error {
			panic("should not be called")
		}

		batchPipeline := make(chan *MessageContext, 1)

		msg := &MessageContext{
			done: make(chan struct{}),
			err:  errors.New("New error"),
		}
		close(msg.done)
		batchPipeline <- msg

		err := readAndCommitBatchPipelineResults(ctx, r, batchPipeline, &nopLog)
		assert.ErrorIs(t, err, msg.err)

		close(batchPipeline)
		err = readAndCommitBatchPipelineResults(ctx, r, batchPipeline, &nopLog)
		assert.ErrorIs(t, err, io.EOF)
	})

	t.Run("CommitErrorStopsReading", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		r := &testMessageReader{}

		emitErr := errors.New("emit error")

		r.commit = func(msgs []kafka.Message) error {
			assert.Equal(t, 1, len(msgs))
			assert.Equal(t, "testA", msgs[0].Topic)
			return emitErr
		}

		batchPipeline := make(chan *MessageContext, 1)

		msg := &MessageContext{
			msg:  kafka.Message{Topic: "testA"},
			done: make(chan struct{}),
		}
		close(msg.done)
		batchPipeline <- msg

		err := readAndCommitBatchPipelineResults(ctx, r, batchPipeline, &nopLog)
		assert.ErrorIs(t, err, emitErr)
	})

	// check context cancel exits blocking read of batchPipeline arg.
	t.Run("ContextCancelStops", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())

		r := &testMessageReader{}

		r.commit = func(msgs []kafka.Message) error {
			panic("should not be called")
		}

		batchPipeline := make(chan *MessageContext)
		readErr := make(chan error)
		go func() {
			readErr <- readAndCommitBatchPipelineResults(ctx, r, batchPipeline, &nopLog)
		}()

		cancel()
		err := <-readErr
		assert.Equal(t, ctx.Err(), err)
	})

	// check context cancel exits blocking read of MessageContext.done
	t.Run("ContextCancelStops2", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())

		r := &testMessageReader{}

		r.commit = func(msgs []kafka.Message) error {
			panic("should not be called")
		}

		batchPipeline := make(chan *MessageContext)
		readErr := make(chan error)
		go func() {
			readErr <- readAndCommitBatchPipelineResults(ctx, r, batchPipeline, &nopLog)
		}()

		msg := &MessageContext{
			msg:  kafka.Message{Topic: "testA"},
			done: make(chan struct{}),
		}
		batchPipeline <- msg

		// As batchPipeline has zero capacity, we can be here only after
		// readAndCommitBatchPipelineResults received from the channel.
		// Cancelling context at this point should stop the blocking read from
		// msg.done.
		cancel()

		err := <-readErr
		assert.Equal(t, ctx.Err(), err)
	})

}
