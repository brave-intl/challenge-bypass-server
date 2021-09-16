package kafka

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	batgo_kafka "github.com/brave-intl/bat-go/utils/kafka"
	"github.com/brave-intl/challenge-bypass-server/server"
	"github.com/segmentio/kafka-go"
	"github.com/sirupsen/logrus"
)

var brokers []string

type Processor func([]byte, string, *server.Server, *logrus.Logger)

type TopicMapping struct {
	Topic       string
	ResultTopic string
	Processor   Processor
	Group       string
}

func StartConsumers(server *server.Server, logger *logrus.Logger) error {
	env := os.Getenv("ENV")
	if env == "" {
		env = "development"
	}
	logger.Infof("Starting %s Kafka consumers", env)
	topicMappings := []TopicMapping{
		TopicMapping{
			Topic:       "request.redeem." + env + ".cbp",
			ResultTopic: "result.redeem." + env + ".cbp",
			Processor:   BlindedTokenRedeemHandler,
			Group:       "cbpProcessors",
		},
		TopicMapping{
			Topic:       "request.sign." + env + ".cbp",
			ResultTopic: "result.sign." + env + ".cbp",
			Processor:   BlindedTokenIssuerHandler,
			Group:       "cbpProcessors",
		},
	}

	for _, topicMapping := range topicMappings {
		// This has to be outside the goroutine to ensure that each consumer gets
		// different values. @TODO: Figure out why this is. If this is inside the
		// goroutine all consumers use the same topicMapping values.
		consumer := newConsumer(topicMapping.Topic, topicMapping.Group, logger)
		go func() {
			var (
				failureCount = 0
				failureLimit = 10
			)
			for {
				// `ReadMessage` blocks until the next event. Do not block main.
				msg, err := consumer.ReadMessage(context.Background())
				if err != nil {
					logger.Error(err.Error())
					if failureCount > failureLimit {
						break
					}
					failureCount++
					continue
				}
				logger.Infof("Processing message")
				go topicMapping.Processor(msg.Value, topicMapping.ResultTopic, server, logger)
			}
		}()
	}
	return nil
}

// NewConsumer returns a Kafka reader configured for the given topic and group.
func newConsumer(topic string, groupId string, logger *logrus.Logger) *kafka.Reader {
	var dialer *kafka.Dialer
	brokers = strings.Split(os.Getenv("KAFKA_BROKERS"), ",")
	if os.Getenv("ENV") != "local" {
		tlsDialer, _, err := batgo_kafka.TLSDialer()
		dialer = tlsDialer
		if err != nil {
			logger.Errorf("Failed to initialize TLS dialer: %e", err)
		}
	}
	logger.Infof("Subscribing to kafka topic %s on behalf of group %s using brokers %s", topic, groupId, brokers)
	kafkaLogger := logrus.New()
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        brokers,
		Dialer:         dialer,
		GroupTopics:    []string{topic},
		GroupID:        groupId,
		StartOffset:    -2,
		ErrorLogger:    kafkaLogger,
		MaxWait:        time.Millisecond * 200,
		CommitInterval: time.Second, // flush commits to Kafka every second
		MinBytes:       1e6,         // 4MB
		MaxBytes:       4e6,         // 4MB
	})
	return reader
}

// Emit sends a message over the Kafka interface.
func Emit(topic string, message []byte, logger *logrus.Logger) error {
	logger.Infof("Beginning data emission for topic %s", topic)
	partition := 0

	if len(brokers) < 1 {
		return fmt.Errorf("At least one kafka broker must be set")
	}
	conn, err := kafka.DialLeader(context.Background(), "tcp", brokers[0], topic, partition)
	if err != nil {
		logger.Fatal("Failed to dial leader:", err)
		return err
	}

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.WriteMessages(
		kafka.Message{Value: []byte(message)},
	)
	if err != nil {
		logger.Fatal("Failed to write messages:", err)
		return err
	}

	if err := conn.Close(); err != nil {
		logger.Fatal("Failed to close writer:", err)
		return err
	}
	logger.Info("Data emitted")
	return nil
}
