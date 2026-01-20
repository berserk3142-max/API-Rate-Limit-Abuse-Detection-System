package kafka

import (
	"context"
	"encoding/json"
	"log"

	"github.com/segmentio/kafka-go"
)

type Consumer struct {
	reader  *kafka.Reader
	handler EventHandler
}

type EventHandler interface {
	HandleAbuseEvent(ctx context.Context, event *AbuseEvent) error
}

func NewConsumer(brokers []string, topic string, groupID string, handler EventHandler) *Consumer {
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  brokers,
		Topic:    topic,
		GroupID:  groupID,
		MinBytes: 10e3,
		MaxBytes: 10e6,
	})

	return &Consumer{
		reader:  reader,
		handler: handler,
	}
}

func (c *Consumer) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				msg, err := c.reader.ReadMessage(ctx)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					log.Printf("error reading message: %v", err)
					continue
				}

				var event AbuseEvent
				if err := json.Unmarshal(msg.Value, &event); err != nil {
					log.Printf("error unmarshaling event: %v", err)
					continue
				}

				if err := c.handler.HandleAbuseEvent(ctx, &event); err != nil {
					log.Printf("error handling event: %v", err)
				}
			}
		}
	}()
}

func (c *Consumer) Close() error {
	return c.reader.Close()
}

type DefaultEventHandler struct{}

func (h *DefaultEventHandler) HandleAbuseEvent(ctx context.Context, event *AbuseEvent) error {
	log.Printf("Received abuse event: type=%s, ip=%s, user=%s, score=%.2f",
		event.EventType, event.IP, event.UserID, event.AnomalyScore)
	return nil
}
