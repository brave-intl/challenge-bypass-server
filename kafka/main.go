// Package kafka manages kafka interaction
package kafka

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	batgo_kafka "github.com/brave-intl/bat-go/libs/kafka"
	"github.com/brave-intl/challenge-bypass-server/server"
	uuid "github.com/google/uuid"
	"github.com/rs/zerolog"
	kafkaGo "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/aws_msk_iam_v2"
)

var brokers []string

// Processor is a function that is used to process Kafka messages on
type Processor func(context.Context, kafkaGo.Message, *zerolog.Logger) error

// Subset of kafka.Reader methods that we use. This is used for testing.
type messageReader interface {
	FetchMessage(ctx context.Context) (kafkaGo.Message, error)
	Stats() kafkaGo.ReaderStats
}

// TopicMapping represents a kafka topic, how to process it, and where to emit the result.
type TopicMapping struct {
	Topic     string
	Processor Processor
}

// MessageContext is used for channel coordination when processing batches of messages
type MessageContext struct {
	// The channel to close when the message is processed.
	done chan struct{}
	err  error
	msg  kafkaGo.Message
}

// StartConsumers reads configuration variables and starts the associated kafka consumers
func StartConsumers(ctx context.Context, providedServer *server.Server, logger *zerolog.Logger) error {
	adsRequestRedeemV1Topic := os.Getenv("REDEEM_CONSUMER_TOPIC")
	adsResultRedeemV1Topic := os.Getenv("REDEEM_PRODUCER_TOPIC")
	adsRequestSignV1Topic := os.Getenv("SIGN_CONSUMER_TOPIC")
	adsResultSignV1Topic := os.Getenv("SIGN_PRODUCER_TOPIC")
	adsConsumerGroupV1 := os.Getenv("CONSUMER_GROUP")

	if len(brokers) < 1 {
		brokers = strings.Split(os.Getenv("VPC_KAFKA_BROKERS"), ",")
	}

	redeemDialer, err := getDialer(ctx, logger)
	if err != nil {
		return fmt.Errorf("failed to get redeem dialer: %w", err)
	}
	redeemWriter := kafkaGo.NewWriter(kafkaGo.WriterConfig{
		Brokers: brokers,
		Topic:   adsResultRedeemV1Topic,
		Dialer:  redeemDialer,
	})

	signDialer, err := getDialer(ctx, logger)
	if err != nil {
		return fmt.Errorf("failed to get sign dialer: %w", err)
	}
	signWriter := kafkaGo.NewWriter(kafkaGo.WriterConfig{
		Brokers: brokers,
		Topic:   adsResultSignV1Topic,
		Dialer:  signDialer,
	})
	topicMappings := []TopicMapping{
		{
			Topic: adsRequestRedeemV1Topic,
			Processor: func(ctx context.Context, msg kafkaGo.Message,
				logger *zerolog.Logger) error {
				return SignedTokenRedeemHandler(ctx, msg, redeemWriter, providedServer, logger)
			},
		},
		{
			Topic: adsRequestSignV1Topic,
			Processor: func(ctx context.Context, msg kafkaGo.Message,
				logger *zerolog.Logger) error {
				return SignedBlindedTokenIssuerHandler(ctx, msg, signWriter, providedServer, logger)
			},
		},
	}
	var topics []string
	for _, topicMapping := range topicMappings {
		topics = append(topics, topicMapping.Topic)
	}

	reader, err := newConsumer(ctx, topics, adsConsumerGroupV1, logger)
	if err != nil {
		return fmt.Errorf("failed to get shared consumer dialer: %w", err)
	}

	batchPipeline := make(chan *MessageContext, 400)
	go processMessagesIntoBatchPipeline(ctx, topicMappings, reader, batchPipeline, logger)
	for {
		err := readAndCommitBatchPipelineResults(ctx, reader, batchPipeline, logger)
		if err != nil {
			// If readAndCommitBatchPipelineResults returns an error.
			close(batchPipeline)
			return err
		}
	}
}

// readAndCommitBatchPipelineResults does a blocking read of the batchPipeline channel and
// then does a blocking read of the done field in the MessageContext in the batchPipeline.
// When an error appears it means that the channel was closed or a temporary error was
// encountered. In the case of a temporary error, the application returns an error without
// committing so that the next reader gets the same message to try again.
func readAndCommitBatchPipelineResults(
	ctx context.Context,
	reader *kafkaGo.Reader,
	batchPipeline chan *MessageContext,
	logger *zerolog.Logger,
) error {
	msgCtx := <-batchPipeline
	<-msgCtx.done

	if msgCtx.err != nil {
		logger.Error().Err(msgCtx.err).Msg("temporary failure encountered")
		return fmt.Errorf("temporary failure encountered: %w", msgCtx.err)
	}
	logger.Info().Msgf("Committing offset %d", msgCtx.msg.Offset)
	if err := reader.CommitMessages(ctx, msgCtx.msg); err != nil {
		logger.Error().Err(err).Msg("failed to commit")
		return errors.New("failed to commit")
	}
	return nil
}

// processMessagesIntoBatchPipeline fetches messages from Kafka indefinitely,
// pushes a MessageContext into the batchPipeline to maintain message order, and
// then spawns a goroutine that will process the message and push to errorResult
// of the MessageContext when the processing completes.
func processMessagesIntoBatchPipeline(ctx context.Context,
	topicMappings []TopicMapping,
	reader messageReader,
	batchPipeline chan *MessageContext,
	logger *zerolog.Logger,
) {
	// Loop forever
	for {
		msg, err := reader.FetchMessage(ctx)
		if err != nil {
			// Indicates batch has no more messages. End the loop for
			// this batch and fetch another.
			if err == io.EOF {
				logger.Info().Msg("Batch complete")
			} else if errors.Is(err, context.DeadlineExceeded) {
				logger.Error().Err(err).Msg("batch item error")
				panic("failed to fetch kafka messages and closed channel")
			}
			// There are other possible errors, but the underlying consumer
			// group handler handle retryable failures well. If further
			// investigation is needed you can review the handler here:
			// https://github.com/segmentio/kafka-go/blob/main/consumergroup.go#L729
			continue
		}
		msgCtx := &MessageContext{
			done: make(chan struct{}),
			msg:  msg,
		}
		// If batchPipeline has been closed by an error in readAndCommitBatchPipelineResults,
		// this write will panic, which is desired behavior, as the rest of the context
		// will also have died and will be restarted from kafka/main.go
		batchPipeline <- msgCtx
		logger.Debug().Msgf("Processing message for topic %s at offset %d", msg.Topic, msg.Offset)
		logger.Debug().Msgf("Reader Stats: %#v", reader.Stats())
		logger.Debug().Msgf("topicMappings: %+v", topicMappings)
		go runMessageProcessor(ctx, msgCtx, topicMappings, logger)
	}
}

// The function to execute the processor defined by a topicMapping on a provided
// message. This runs on own goroutine and closes msgCtx.done to signal
// completion. It keeps msgCtx.err as nil in cases of success or permanent
// failures and will set msgCtx.err in the case that a temporary error is
// encountered.
func runMessageProcessor(
	ctx context.Context,
	msgCtx *MessageContext,
	topicMappings []TopicMapping,
	logger *zerolog.Logger,
) {
	defer close(msgCtx.done)
	msg := msgCtx.msg
	for _, topicMapping := range topicMappings {
		logger.Debug().Msgf("topic: %+v, topicMapping: %+v", msg.Topic, topicMapping.Topic)
		if msg.Topic == topicMapping.Topic {
			msgCtx.err = topicMapping.Processor(ctx, msg, logger)
			return
		}
	}
	// This is a permanent error, so do not set msgCtx.err to commit the
	// received message.
	logger.Error().Msgf("topic received whose topic is not configured: %s", msg.Topic)
}

// NewConsumer returns a Kafka reader configured for the given topic and group.
func newConsumer(ctx context.Context, topics []string, groupID string, logger *zerolog.Logger) (*kafkaGo.Reader, error) {
	brokers = strings.Split(os.Getenv("VPC_KAFKA_BROKERS"), ",")
	logger.Info().Msgf("Subscribing to kafka topic %s on behalf of group %s using brokers %s", topics, groupID, brokers)
	dialer, err := getDialer(ctx, logger)
	if err != nil {
		return nil, err
	}
	reader := kafkaGo.NewReader(kafkaGo.ReaderConfig{
		Brokers:        brokers,
		Dialer:         dialer,
		GroupTopics:    topics,
		GroupID:        groupID,
		StartOffset:    kafkaGo.FirstOffset,
		Logger:         logger,
		MaxWait:        time.Second * 20, // default 20s
		CommitInterval: time.Second,      // flush commits to Kafka every second
		MinBytes:       1e3,              // 1KB
		MaxBytes:       10e6,             // 10MB
	})
	logger.Trace().Msgf("Reader created with subscription")
	return reader, nil
}

// Emit sends a message over the Kafka interface.
func Emit(
	ctx context.Context,
	producer *kafkaGo.Writer,
	message []byte,
	logger *zerolog.Logger,
) error {
	logger.Info().Msgf("Beginning data emission for topic %s", producer.Topic)

	messageKey := uuid.New()
	marshaledMessageKey, err := messageKey.MarshalBinary()
	if err != nil {
		logger.Error().Msgf("failed to marshal UUID into binary. Using default key value: %e", err)
		marshaledMessageKey = []byte("default")
	}

	err = producer.WriteMessages(
		ctx,
		kafkaGo.Message{
			Value: []byte(message),
			Key:   []byte(marshaledMessageKey),
		},
	)
	if err != nil {
		logger.Error().Msgf("failed to write messages: %e", err)
		return err
	}

	logger.Info().Msg("Data emitted")
	return nil
}

// getDialer returns a reference to a Kafka dialer. The dialer is TLS enabled in non-local
// environments.
func getDialer(ctx context.Context, logger *zerolog.Logger) (*kafkaGo.Dialer, error) {
	var dialer *kafkaGo.Dialer
	env := os.Getenv("ENV")
	if env != "local" {
		logger.Info().Msg("Generating TLSDialer")
		var cfg aws.Config
		var err error

		if env == "development" {
			cfg, err = awsConfig.LoadDefaultConfig(
				ctx,
				awsConfig.WithRegion(os.Getenv("AWS_DEFAULT_REGION")),
			)
		} else {
			cfg, err = awsConfig.LoadDefaultConfig(ctx)
		}

		if err != nil {
			logger.Error().Msgf("failed to setup aws config: %e", err)
			return nil, err
		}

		mechanism := aws_msk_iam_v2.NewMechanism(cfg)
		tlsDialer, _, err := batgo_kafka.TLSDialer()
		dialer = tlsDialer
		dialer.SASLMechanism = mechanism

		if err != nil {
			logger.Error().Msgf("failed to initialize TLS dialer: %e", err)
			return nil, err
		}
	} else {
		logger.Info().Msg("Generating Dialer")
		dialer = &kafkaGo.Dialer{
			Timeout:   10 * time.Second,
			DualStack: true,
		}
	}
	return dialer, nil
}
