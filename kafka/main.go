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

	batchPipeline := make(chan *MessageContext)
	ctx := context.Background()
	go processMessagesIntoBatchPipeline(ctx, topicMappings, providedServer, reader, batchPipeline, logger)
	for {
		readAndCommitBatchPipelineResults(ctx, reader, batchPipeline, logger)
	}
}

// readAndCommitBatchPipelineResults does a blocking read of the batchPipeline channel and
// then does a blocking read of the errorResult in the MessageContext in the batchPipeline.
// When an error appears it means that the message processing has entered a finalized state
// and is either ready to be committed or has encountered a remporary error. In the case
// of a temporary error, the application panics without committing so that the next reader
// gets the same message to try again.
func readAndCommitBatchPipelineResults(
	ctx context.Context,
	reader *kafka.Reader,
	batchPipeline chan *MessageContext,
	logger *zerolog.Logger,
) {
	msgCtx := <-batchPipeline
	err := <-msgCtx.errorResult
	if !err.Temporary {
		logger.Info().Msgf("Committing offset %d", msgCtx.msg.Offset)
		if err := reader.CommitMessages(ctx, msgCtx.msg); err != nil {
			logger.Error().Err(err).Msg("failed to commit")
			panic("failed to commit")
		}
	}
	logger.Error().Msg("temporary failure encountered")
	panic("temporary failure encountered")
}

// processMessagesIntoBatchPipeline fetches messages from Kafka indefinitely, pushes a
// MessageContext into the batchPipeline to maintain message order, and then spawns a
// goroutine that will process the message and push to errorResult of the MessageContext
// when the processing completes. There *must* be a value pushed to the errorResult, so
// a simple ProcessingError is created for the success case.
func processMessagesIntoBatchPipeline(
	ctx context.Context,
	topicMappings []TopicMapping,
	providedServer *server.Server,
	reader *kafka.Reader,
	batchPipeline chan *MessageContext,
	logger *zerolog.Logger,
) {
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
				go processMessageIntoErrorResultChannel(
					msg,
					topicMapping,
					providedServer,
					msgCtx.errorResult,
					logger,
				)
			}
		}
	}
}

// processMessageIntoErrorResultChannel executes the processor defined by a topicMapping
// on a provided message. It then puts the result into the errChan in the event that an
// error occurs, or places an error placeholder into the channel in case of success.
func processMessageIntoErrorResultChannel(
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
