// Package kafka manages kafka interaction
package kafka

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/brave-intl/challenge-bypass-server/server"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	kafkaGo "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/aws_msk_iam_v2"
)

var brokers []string

// Processor is a function that is used to process Kafka messages on
type Processor func(context.Context, kafkaGo.Message, *slog.Logger) error

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

var (
	tokenIssuanceRequestTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cbp_token_issuance_request_total",
		Help: "Number of requests for new tokens",
	})
	tokenIssuanceFailureTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cbp_token_issuance_failure_total",
		Help: "Number of token requests that failed",
	})
	tokenRedeemRequestTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cbp_token_redeem_request_total",
		Help: "Number of requests for token redemption",
	})
	tokenRedeemFailureTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cbp_token_redeem_failure_total",
		Help: "Number of tokens redeemed",
	})
	duplicateRedemptionTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cbp_duplicate_redemption_total",
		Help: `Number of tokens requested for redemption after already being
		processed, but with modified request information. This is malicious and
		should be rare.`,
	})
	idempotentRedemptionTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cbp_idempotent_redemption_total",
		Help: `Number of identical tokens requested for redemption. This is an
		innocent retry.`,
	})
	rebootFromPanicTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cbp_reboot_from_panic_total",
		Help: `There is a case where the current expected behavior is to panic
		to avoid any chance of committing a bad offset to Kafka. This counts
		that case.`,
	})
	kafkaErrorTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cbp_kafka_error_total",
		Help: `Total errors in the Kafka processor of any kind. This counter is
		incremented liberally and may double-count an error that is returned up
		the stack.`,
	})
)

// StartConsumers reads configuration variables and starts the associated kafka consumers
func StartConsumers(ctx context.Context, providedServer *server.Server, logger *slog.Logger) error {
	adsRequestRedeemV1Topic := os.Getenv("REDEEM_CONSUMER_TOPIC")
	adsResultRedeemV1Topic := os.Getenv("REDEEM_PRODUCER_TOPIC")
	adsRequestSignV1Topic := os.Getenv("SIGN_CONSUMER_TOPIC")
	adsResultSignV1Topic := os.Getenv("SIGN_PRODUCER_TOPIC")
	adsConsumerGroupV1 := os.Getenv("CONSUMER_GROUP")

	//var prometheusRegistry prometheus.Registerer
	//if os.Getenv("ENV") == "local" || os.Getenv("ENV") == "test" {
	//	prometheusRegistry = prometheus.NewRegistry()
	//} else {
	//	prometheusRegistry = prometheus.DefaultRegisterer
	//}

	//prometheusRegistry.MustRegister(tokenIssuanceRequestTotal)
	//prometheusRegistry.MustRegister(tokenIssuanceFailureTotal)
	//prometheusRegistry.MustRegister(tokenRedeemRequestTotal)
	//prometheusRegistry.MustRegister(tokenRedeemFailureTotal)
	//prometheusRegistry.MustRegister(duplicateRedemptionTotal)
	//prometheusRegistry.MustRegister(idempotentRedemptionTotal)
	//prometheusRegistry.MustRegister(rebootFromPanicTotal)
	//prometheusRegistry.MustRegister(kafkaErrorTotal)

	if len(brokers) < 1 {
		brokers = strings.Split(os.Getenv("VPC_KAFKA_BROKERS"), ",")
	}

	redeemDialer, err := getDialer(ctx, logger)
	if err != nil {
		kafkaErrorTotal.Inc()
		return fmt.Errorf("failed to get redeem dialer: %w", err)
	}
	redeemWriter := kafkaGo.NewWriter(kafkaGo.WriterConfig{
		Brokers: brokers,
		Topic:   adsResultRedeemV1Topic,
		Dialer:  redeemDialer,
	})

	signDialer, err := getDialer(ctx, logger)
	if err != nil {
		kafkaErrorTotal.Inc()
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
				logger *slog.Logger) error {
				tokenRedeemRequestTotal.Inc()
				err := SignedTokenRedeemHandler(ctx, msg, redeemWriter, providedServer, logger)
				if err != nil {
					tokenRedeemFailureTotal.Inc()
				}
				return err
			},
		},
		{
			Topic: adsRequestSignV1Topic,
			Processor: func(ctx context.Context, msg kafkaGo.Message,
				logger *slog.Logger) error {
				tokenIssuanceRequestTotal.Inc()
				err := SignedBlindedTokenIssuerHandler(ctx, msg, signWriter, providedServer, logger)
				if err != nil {
					tokenIssuanceFailureTotal.Inc()
				}
				return err
			},
		},
	}
	var topics []string
	for _, topicMapping := range topicMappings {
		topics = append(topics, topicMapping.Topic)
	}

	reader, err := newConsumer(ctx, topics, adsConsumerGroupV1, logger)
	if err != nil {
		kafkaErrorTotal.Inc()
		return fmt.Errorf("failed to get shared consumer dialer: %w", err)
	}

	batchPipeline := make(chan *MessageContext, 400)
	go processMessagesIntoBatchPipeline(ctx, topicMappings, reader, batchPipeline, logger)
	for {
		err := readAndCommitBatchPipelineResults(ctx, reader, batchPipeline, logger)
		if err != nil {
			logger.Error("failed to process batch pipeline", slog.Any("error", err))
			// If readAndCommitBatchPipelineResults returns an error.
			close(batchPipeline)
			kafkaErrorTotal.Inc()
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
	logger *slog.Logger,
) error {
	msgCtx := <-batchPipeline
	<-msgCtx.done

	if msgCtx.err != nil {
		kafkaErrorTotal.Inc()
		return fmt.Errorf("temporary failure encountered: %w", msgCtx.err)
	}
	logger.Debug("committing offset", "offset", msgCtx.msg.Offset)
	if err := reader.CommitMessages(ctx, msgCtx.msg); err != nil {
		kafkaErrorTotal.Inc()
		return fmt.Errorf("failed to commit: %w", err)
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
	logger *slog.Logger,
) {
	// Catch the panic cases in order to count them, but continue to panic.
	defer func() {
		if r := recover(); r != nil {
			rebootFromPanicTotal.Inc()
			panic(r) // Re-panic to ensure termination
		}
	}()
	// Loop forever
	for {
		msg, err := reader.FetchMessage(ctx)
		if err != nil {
			// Indicates batch has no more messages. End the loop for
			// this batch and fetch another.
			if err == io.EOF {
				logger.Debug("batch complete")
			} else if errors.Is(err, context.DeadlineExceeded) {
				kafkaErrorTotal.Inc()
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
		logger.Debug("processing message", "topic", msg.Topic, "offset", msg.Offset)
		logger.Debug("reader Stats", slog.Any("stats", reader.Stats()))
		logger.Debug("topic mappings", slog.Any("topicMappings", topicMappings))
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
	logger *slog.Logger,
) {
	defer close(msgCtx.done)
	msg := msgCtx.msg
	for _, topicMapping := range topicMappings {
		logger.Debug("iterating topic mapping", "topic", msg.Topic, "topicMapping", topicMapping.Topic)
		if msg.Topic == topicMapping.Topic {
			msgCtx.err = topicMapping.Processor(ctx, msg, logger)
			return
		}
	}
	// This is a permanent error, so do not set msgCtx.err to commit the
	// received message.
	logger.Error("topic received whose topic is not configured", slog.Any("topic", msg.Topic))
	kafkaErrorTotal.Inc()
}

// NewConsumer returns a Kafka reader configured for the given topic and group.
func newConsumer(ctx context.Context, topics []string, groupID string, logger *slog.Logger) (*kafkaGo.Reader, error) {
	brokers = strings.Split(os.Getenv("VPC_KAFKA_BROKERS"), ",")
	logger.Info("subscribing",
		"topics", topics,
		"group", groupID,
		"brokers", brokers,
	)
	dialer, err := getDialer(ctx, logger)
	if err != nil {
		kafkaErrorTotal.Inc()
		return nil, err
	}
	// kafka-go's ReaderConfig requires the old styl log.Logger
	// We can make one from our slog.Logger.
	logLogger := slog.NewLogLogger(logger.Handler(), slog.LevelInfo)
	reader := kafkaGo.NewReader(kafkaGo.ReaderConfig{
		Brokers:        brokers,
		Dialer:         dialer,
		GroupTopics:    topics,
		GroupID:        groupID,
		StartOffset:    kafkaGo.FirstOffset,
		Logger:         logLogger,
		MaxWait:        time.Second * 20, // default 20s
		CommitInterval: time.Second,      // flush commits to Kafka every second
		MinBytes:       1e3,              // 1KB
		MaxBytes:       10e6,             // 10MB
	})
	logger.Debug("reader created with subscription")
	return reader, nil
}

// Emit sends a message over the Kafka interface.
func Emit(
	ctx context.Context,
	producer *kafkaGo.Writer,
	message []byte,
	logger *slog.Logger,
) error {
	logger.Info("beginning data emission", "topic", producer.Topic)

	messageKey := uuid.New()
	marshaledMessageKey, err := messageKey.MarshalBinary()
	if err != nil {
		logger.Error(
			"failed to marshal UUID into binary using default key value",
			slog.Any("error", err),
		)
		kafkaErrorTotal.Inc()
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
		kafkaErrorTotal.Inc()
		return fmt.Errorf("failed to write messages: %w", err)
	}

	logger.Debug("data emitted")
	return nil
}

// getDialer returns a reference to a Kafka dialer. The dialer is TLS enabled in non-local
// environments.
func getDialer(ctx context.Context, logger *slog.Logger) (*kafkaGo.Dialer, error) {
	env := os.Getenv("ENV")
	if env != "local" && env != "test" {
		logger.Debug("generating TLSDialer")
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
			kafkaErrorTotal.Inc()
			return nil, fmt.Errorf("failed to setup aws config: %w", err)
		}

		return &kafkaGo.Dialer{
			Timeout:       10 * time.Second,
			DualStack:     true,
			SASLMechanism: aws_msk_iam_v2.NewMechanism(cfg),
			TLS: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}, nil
	} else {
		logger.Debug("generating Dialer")
		return &kafkaGo.Dialer{
			Timeout:   10 * time.Second,
			DualStack: true,
		}, nil
	}
}
