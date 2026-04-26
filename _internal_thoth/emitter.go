package thoth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

const (
	emitterBufSize  = 1000
	emitterBatchMax = 10
	maxErrorBodyLen = 512
)

// sqsSender is the interface used by SQSEmitter (enables test doubles).
type sqsSender interface {
	SendMessageBatch(ctx context.Context, params *sqs.SendMessageBatchInput, optFns ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error)
}

// SQSEmitter batches BehavioralEvents and sends them to an SQS FIFO queue.
// Emit is non-blocking; events are dropped when the buffer is full.
// Call Close() to flush remaining events and stop the background goroutine.
type SQSEmitter struct {
	queueURL string
	sender   sqsSender
	ch       chan *BehavioralEvent
	wg       sync.WaitGroup
}

// NewSQSEmitter creates an emitter and starts the background drain goroutine.
// Pass an empty queueURL to create a no-op emitter.
func NewSQSEmitter(ctx context.Context, queueURL string, sender sqsSender) *SQSEmitter {
	e := &SQSEmitter{
		queueURL: queueURL,
		sender:   sender,
		ch:       make(chan *BehavioralEvent, emitterBufSize),
	}
	e.wg.Add(1)
	go e.drainLoop(ctx)
	return e
}

// Emit enqueues an event. Non-blocking; drops the event if the buffer is full.
func (e *SQSEmitter) Emit(event *BehavioralEvent) {
	if e.queueURL == "" {
		return
	}
	select {
	case e.ch <- event:
	default:
		slog.Error("thoth: emitter buffer full, dropping event", "event_id", event.EventID, "dropped", true)
	}
}

// Close flushes remaining events and stops the background goroutine.
func (e *SQSEmitter) Close() {
	close(e.ch)
	e.wg.Wait()
}

func (e *SQSEmitter) drainLoop(ctx context.Context) {
	defer e.wg.Done()
	for {
		batch := e.collectBatch()
		if len(batch) == 0 {
			return
		}
		e.sendBatch(ctx, batch)
	}
}

func (e *SQSEmitter) collectBatch() []*BehavioralEvent {
	var batch []*BehavioralEvent
	event, ok := <-e.ch
	if !ok {
		return nil
	}
	batch = append(batch, event)
	for len(batch) < emitterBatchMax {
		select {
		case event, ok := <-e.ch:
			if !ok {
				return batch
			}
			batch = append(batch, event)
		default:
			return batch
		}
	}
	return batch
}

func (e *SQSEmitter) sendBatch(ctx context.Context, events []*BehavioralEvent) {
	entries := make([]types.SendMessageBatchRequestEntry, 0, len(events))
	for i, ev := range events {
		body, err := json.Marshal(ev)
		if err != nil {
			slog.Error("thoth: failed to marshal event; dropping event", "event_id", ev.EventID, "err", err, "dropped", true)
			continue
		}
		entries = append(entries, types.SendMessageBatchRequestEntry{
			Id:                     aws.String(fmt.Sprintf("%d", i)),
			MessageBody:            aws.String(string(body)),
			MessageGroupId:         aws.String(ev.SessionID),
			MessageDeduplicationId: aws.String(ev.EventID),
		})
	}
	if len(entries) == 0 {
		return
	}
	if _, err := e.sender.SendMessageBatch(ctx, &sqs.SendMessageBatchInput{
		QueueUrl: aws.String(e.queueURL),
		Entries:  entries,
	}); err != nil {
		slog.Error("thoth: failed to send batch; events dropped", "count", len(entries), "err", err, "dropped", true)
	}
}

// HTTPEmitter batches BehavioralEvents and POSTs them to the hosted Thoth API.
// Emit is non-blocking; events are dropped when the buffer is full.
// Call Close() to flush remaining events and stop the background goroutine.
type HTTPEmitter struct {
	endpoint string
	apiKey   string
	http     *http.Client
	ch       chan *BehavioralEvent
	wg       sync.WaitGroup
}

// NewHTTPEmitter creates an HTTPEmitter that sends events to {apiURL}/v1/events/batch
// with Bearer token authentication. Starts a background drain goroutine.
func NewHTTPEmitter(apiURL, apiKey string) *HTTPEmitter {
	e := &HTTPEmitter{
		endpoint: strings.TrimRight(apiURL, "/") + "/v1/events/batch",
		apiKey:   apiKey,
		http:     &http.Client{},
		ch:       make(chan *BehavioralEvent, emitterBufSize),
	}
	e.wg.Add(1)
	go e.drainLoop()
	return e
}

// Emit enqueues an event. Non-blocking; drops the event if the buffer is full.
func (e *HTTPEmitter) Emit(event *BehavioralEvent) {
	select {
	case e.ch <- event:
	default:
		slog.Error("thoth: http emitter buffer full, dropping event", "event_id", event.EventID, "dropped", true)
	}
}

// Close flushes remaining events and stops the background goroutine.
func (e *HTTPEmitter) Close() {
	close(e.ch)
	e.wg.Wait()
}

func (e *HTTPEmitter) drainLoop() {
	defer e.wg.Done()
	for {
		batch := e.collectBatch()
		if len(batch) == 0 {
			return
		}
		e.sendBatch(batch)
	}
}

func (e *HTTPEmitter) collectBatch() []*BehavioralEvent {
	var batch []*BehavioralEvent
	event, ok := <-e.ch
	if !ok {
		return nil
	}
	batch = append(batch, event)
	for len(batch) < emitterBatchMax {
		select {
		case event, ok := <-e.ch:
			if !ok {
				return batch
			}
			batch = append(batch, event)
		default:
			return batch
		}
	}
	return batch
}

func (e *HTTPEmitter) sendBatch(events []*BehavioralEvent) {
	payload := struct {
		Events []*BehavioralEvent `json:"events"`
	}{Events: events}

	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("thoth: http emitter marshal error; events dropped", "count", len(events), "err", err, "dropped", true)
		return
	}

	req, err := http.NewRequest(http.MethodPost, e.endpoint, bytes.NewReader(body))
	if err != nil {
		slog.Error("thoth: http emitter request build error; events dropped", "count", len(events), "err", err, "dropped", true)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if e.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.apiKey)
		req.Header.Set("X-Api-Key", e.apiKey)
	}

	resp, err := e.http.Do(req)
	if err != nil {
		slog.Error("thoth: http emitter send error; events dropped", "count", len(events), "err", err, "dropped", true)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody := ""
		bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyLen))
		if readErr != nil {
			errBody = fmt.Sprintf("<read_error:%v>", readErr)
		} else {
			errBody = strings.TrimSpace(string(bodyBytes))
		}
		slog.Error(
			"thoth: http emitter unexpected status; events dropped",
			"status", resp.StatusCode,
			"status_text", resp.Status,
			"url", e.endpoint,
			"response_body", errBody,
			"count", len(events),
			"dropped", true,
		)
	}
}
