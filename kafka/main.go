package kafka

import (
	"context"
	"fmt"
	batgo_kafka "github.com/brave-intl/bat-go/utils/kafka"
	"github.com/brave-intl/challenge-bypass-server/server"
	"github.com/segmentio/kafka-go"
	"github.com/sirupsen/logrus"
	"os"
	"strings"
	"time"
)

var brokers []string

type Processor func([]byte, *server.Server, *logrus.Logger)

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
	topicMappings := []TopicMapping{
		TopicMapping{
			Topic:       "request.redeem.payment." + env + ".cbp",
			ResultTopic: "result.redeem.payment." + env + ".cbp",
			Processor:   func() {},
			Group:       "cbpProcessors",
		},
		TopicMapping{
			Topic:       "request.redeem.confirmation." + env + ".cbp",
			ResultTopic: "result.redeem.payment." + env + ".cbp",
			Processor:   func() {},
			Group:       "cbpProcessors",
		},
		TopicMapping{
			Topic:       "request.sign.payment." + env + ".cbp",
			ResultTopic: "result.redeem.payment." + env + ".cbp",
			Processor:   BlindedTokenIssuerHandler,
			Group:       "cbpProcessors",
		},
		TopicMapping{
			Topic:       "request.sign.confirmation." + env + ".cbp",
			ResultTopic: "result.redeem.payment." + env + ".cbp",
			Processor:   BlindedTokenIssuerHandler,
			Group:       "cbpProcessors",
		},
	}

	for _, topicMapping := range topicMappings {
		go func() {
			consumer := newConsumer(topicMapping.Topic, topicMapping.Group)
			for {
				// `ReadMessage` blocks until the next event. Do not block main.
				msg, err := consumer.ReadMessage(context.Background())
				if err != nil {
					log.Error(err.Error())
					if failureCount > failureLimit {
						break
					}
					failureCount++
					continue
				}
				go topicMapping.Processor(msg.Value, server, logger)
			}
		}()
	}
}

// NewConsumer returns a Kafka reader configured for the given topic and group.
func newConsumer(topic string, groupId string) *kafka.Reader {
	var dialer *kafka.Dialer
	brokers = strings.Split(os.Getenv("KAFKA_BROKERS"), ",")
	if os.Getenv("ENV") != "local" {
		tlsDialer, _, err := batgo_kafka.TLSDialer()
		dialer = tlsDialer
		if err != nil {
			logger.Errorf("Failed to initialize TLS dialer: %e", err)
		}
	}
	logger.Tracef("Subscribing to kafka topic %s on behalf of group %s using brokers %s", topic, groupId, brokers)
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
func Emit(topic string, message []byte) error {
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
	return nil
}
