package kafka

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	batgo_kafka "github.com/brave-intl/bat-go/utils/kafka"
	"github.com/brave-intl/challenge-bypass-server/server"
	"github.com/brave-intl/challenge-bypass-server/utils"
	uuid "github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
	"github.com/sirupsen/logrus"
)

var brokers []string

// Processor is a function that is used to process Kafka messages
type Processor func(
	kafka.Message,
	*kafka.Writer,
	*server.Server,
	*zerolog.Logger,
) *utils.ProcessingError

// ProcessingResult contains a message and the topic to which the message should be
// emitted
type ProcessingResult struct {
	ResultProducer *kafka.Writer
	Message        []byte
	RequestID      string
}

// TopicMapping represents a kafka topic, how to process it, and where to emit the result.
type TopicMapping struct {
	Topic          string
	ResultProducer *kafka.Writer
	Processor      Processor
	Group          string
}

type MessageContext struct {
	errorResult chan *utils.ProcessingError
	msg         kafka.Message
}

// StartConsumers reads configuration variables and starts the associated kafka consumers
func StartConsumers(providedServer *server.Server, logger *zerolog.Logger) error {
	adsRequestRedeemV1Topic := os.Getenv("REDEEM_CONSUMER_TOPIC")
	adsResultRedeemV1Topic := os.Getenv("REDEEM_PRODUCER_TOPIC")
	adsRequestSignV1Topic := os.Getenv("SIGN_CONSUMER_TOPIC")
	adsResultSignV1Topic := os.Getenv("SIGN_PRODUCER_TOPIC")
	adsConsumerGroupV1 := os.Getenv("CONSUMER_GROUP")
	if len(brokers) < 1 {
		brokers = strings.Split(os.Getenv("KAFKA_BROKERS"), ",")
	}
	topicMappings := []TopicMapping{
		{
			Topic: adsRequestRedeemV1Topic,
			ResultProducer: kafka.NewWriter(kafka.WriterConfig{
				Brokers: brokers,
				Topic:   adsResultRedeemV1Topic,
				Dialer:  getDialer(logger),
			}),
			Processor: SignedTokenRedeemHandler,
			Group:     adsConsumerGroupV1,
		},
		{
			Topic: adsRequestSignV1Topic,
			ResultProducer: kafka.NewWriter(kafka.WriterConfig{
				Brokers: brokers,
				Topic:   adsResultSignV1Topic,
				Dialer:  getDialer(logger),
			}),
			Processor: SignedBlindedTokenIssuerHandler,
			Group:     adsConsumerGroupV1,
		},
	}
	var topics []string
	for _, topicMapping := range topicMappings {
		topics = append(topics, topicMapping.Topic)
	}

	reader := newConsumer(topics, adsConsumerGroupV1, logger)

	// `kafka-go` exposes messages one at a time through its normal interfaces despite
	// collecting messages with batching from Kafka. To process these messages in
	// parallel we use the `FetchMessage` method in a loop to collect a set of messages
	// for processing. Successes and permanent failures are committed. Temporary
	// failures are not committed and are retried. Miscategorization of errors can
	// cause the consumer to become stuck forever, so it's important that permanent
	// failures are not categorized as temporary.
	batchPipeline := make(chan *MessageContext)
	ctx := context.Background()
	go func(ctx context.Context) {
		for {
			msg, err := reader.FetchMessage(ctx)
			if err != nil {
				// Indicates batch has no more messages. End the loop for
				// this batch and fetch another.
				if err == io.EOF {
					logger.Info().Msg("Batch complete")
				} else if strings.ToLower(err.Error()) != "context deadline exceeded" {
					logger.Error().Err(err).Msg("batch item error")
					panic("batch item error")
				}
				continue
			}
			msgCtx := &MessageContext{
				errorResult: make(chan *utils.ProcessingError),
				msg:         msg,
			}
			batchPipeline <- msgCtx
			logger.Debug().Msgf("Processing message for topic %s at offset %d", msg.Topic, msg.Offset)
			logger.Debug().Msgf("Reader Stats: %#v", reader.Stats())
			// Check if any of the existing topicMappings match the fetched message
			for _, topicMapping := range topicMappings {
				if msg.Topic == topicMapping.Topic {
					go func(
						msg kafka.Message,
						topicMapping TopicMapping,
						providedServer *server.Server,
						errChan chan *utils.ProcessingError,
						logger *zerolog.Logger,
					) {
						err := topicMapping.Processor(
							msg,
							topicMapping.ResultProducer,
							providedServer,
							logger,
						)
						if err != nil {
							errChan <- err
						} else {
							errChan <- &utils.ProcessingError{
								Temporary: false,
							}
						}
					}(msg, topicMapping, providedServer, msgCtx.errorResult, logger)
				}
			}
		}
	}(ctx)

	for {
		msgCtx := <-batchPipeline
		err := <-msgCtx.errorResult
		if !err.Temporary {
			logger.Info().Msgf("Committing offset %d", msgCtx.msg.Offset)
			if err := reader.CommitMessages(ctx, msgCtx.msg); err != nil {
				logger.Error().Err(err).Msg("failed to commit")
				panic("failed to commit")
			}
		}
	}
}

// NewConsumer returns a Kafka reader configured for the given topic and group.
func newConsumer(topics []string, groupID string, logger *zerolog.Logger) *kafka.Reader {
	brokers = strings.Split(os.Getenv("KAFKA_BROKERS"), ",")
	logger.Info().Msgf("Subscribing to kafka topic %s on behalf of group %s using brokers %s", topics, groupID, brokers)
	kafkaLogger := logrus.New()
	kafkaLogger.SetLevel(logrus.WarnLevel)
	dialer := getDialer(logger)
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        brokers,
		Dialer:         dialer,
		GroupTopics:    topics,
		GroupID:        groupID,
		StartOffset:    kafka.FirstOffset,
		Logger:         kafkaLogger,
		MaxWait:        time.Second * 20, // default 20s
		CommitInterval: time.Second,      // flush commits to Kafka every second
		MinBytes:       1e3,              // 1KB
		MaxBytes:       10e6,             // 10MB
	})
	logger.Trace().Msgf("Reader create with subscription")
	return reader
}

// MayEmitIfPermanent attempts to emit and error message to Kafka if the error is not
// temporary. It logs, but returns nothing on failure.
func MayEmitIfPermanent(
	processingResult *ProcessingResult,
	errorResult *utils.ProcessingError,
	producer *kafka.Writer,
	log *zerolog.Logger,
) {
	if errorResult.Temporary == false {
		err := Emit(producer, processingResult.Message, log)
		if err != nil {
			message := fmt.Sprintf(
				"request %s: failed to emit results to topic %s",
				processingResult.RequestID,
				processingResult.ResultProducer.Topic,
			)
			log.Error().Err(err).Msgf(message)
		}
	}
}

// Emit sends a message over the Kafka interface.
func Emit(producer *kafka.Writer, message []byte, logger *zerolog.Logger) error {
	logger.Info().Msgf("Beginning data emission for topic %s", producer.Topic)

	messageKey := uuid.New()
	marshaledMessageKey, err := messageKey.MarshalBinary()
	if err != nil {
		logger.Error().Msgf("failed to marshal UUID into binary. Using default key value: %e", err)
		marshaledMessageKey = []byte("default")
	}

	err = producer.WriteMessages(
		context.Background(),
		kafka.Message{
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

func getDialer(logger *zerolog.Logger) *kafka.Dialer {
	var dialer *kafka.Dialer
	if os.Getenv("ENV") != "local" {
		logger.Info().Msg("Generating TLSDialer")
		tlsDialer, _, err := batgo_kafka.TLSDialer()
		dialer = tlsDialer
		if err != nil {
			logger.Error().Msgf("failed to initialize TLS dialer: %e", err)
		}
	} else {
		logger.Info().Msg("Generating Dialer")
		dialer = &kafka.Dialer{
			Timeout:   10 * time.Second,
			DualStack: true,
		}
	}
	return dialer
}
