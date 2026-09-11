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
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

const (
	emitterBufSize      = 1000
	emitterBatchMax     = 10
	maxErrorBodyLen     = 512
	emitterMaxAttempts  = 3
	emitterRetryDelay   = 100 * time.Millisecond
	httpEmitterTimeout  = 5 * time.Second
	emitterCloseTimeout = 20 * time.Second
)

type DeliveryStatus struct {
	Pending   uint64
	Delivered uint64
	Dropped   uint64
	Retried   uint64
}

type deliveryTracker struct {
	pending   atomic.Uint64
	delivered atomic.Uint64
	dropped   atomic.Uint64
	retried   atomic.Uint64
}

func (d *deliveryTracker) status() DeliveryStatus {
	return DeliveryStatus{Pending: d.pending.Load(), Delivered: d.delivered.Load(), Dropped: d.dropped.Load(), Retried: d.retried.Load()}
}

func (d *deliveryTracker) complete(delivered, dropped uint64) {
	d.delivered.Add(delivered)
	d.dropped.Add(dropped)
	if completed := delivered + dropped; completed > 0 {
		d.pending.Add(^(completed - 1))
	}
}

// sqsSender is the interface used by SQSEmitter (enables test doubles).
type sqsSender interface {
	SendMessageBatch(ctx context.Context, params *sqs.SendMessageBatchInput, optFns ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error)
}

// SQSEmitter batches BehavioralEvents and sends them to an SQS FIFO queue.
// Emit is non-blocking; events are dropped when the buffer is full.
// Call Close() to flush remaining events and stop the background goroutine.
type SQSEmitter struct {
	queueURL  string
	sender    sqsSender
	ch        chan *BehavioralEvent
	wg        sync.WaitGroup
	done      chan struct{}
	closeOnce sync.Once
	delivery  deliveryTracker
}

// NewSQSEmitter creates an emitter and starts the background drain goroutine.
// Pass an empty queueURL to create a no-op emitter.
func NewSQSEmitter(ctx context.Context, queueURL string, sender sqsSender) *SQSEmitter {
	e := &SQSEmitter{
		queueURL: queueURL,
		sender:   sender,
		ch:       make(chan *BehavioralEvent, emitterBufSize),
		done:     make(chan struct{}),
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
	e.delivery.pending.Add(1)
	select {
	case e.ch <- event:
	default:
		e.delivery.pending.Add(^uint64(0))
		e.delivery.dropped.Add(1)
		slog.Error("thoth: emitter buffer full, dropping event", "event_id", event.EventID, "dropped", true)
	}
}

// Close flushes remaining events and stops the background goroutine.
func (e *SQSEmitter) Close() {
	e.CloseWithTimeout(emitterCloseTimeout)
}

func (e *SQSEmitter) CloseWithTimeout(timeout time.Duration) DeliveryStatus {
	e.closeOnce.Do(func() { close(e.ch) })
	select {
	case <-e.done:
	case <-time.After(timeout):
	}
	return e.Status()
}

func (e *SQSEmitter) Status() DeliveryStatus { return e.delivery.status() }

func (e *SQSEmitter) drainLoop(ctx context.Context) {
	defer e.wg.Done()
	defer close(e.done)
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
		body, err := json.Marshal(minimalTelemetryEvent(ev))
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
	pending := entries
	for attempt := 1; attempt <= emitterMaxAttempts && len(pending) > 0; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, httpEmitterTimeout)
		output, err := e.sender.SendMessageBatch(attemptCtx, &sqs.SendMessageBatchInput{QueueUrl: aws.String(e.queueURL), Entries: pending})
		cancel()
		if err != nil {
			if attempt < emitterMaxAttempts {
				e.delivery.retried.Add(uint64(len(pending)))
				time.Sleep(emitterRetryDelay * time.Duration(attempt))
				continue
			}
			e.delivery.complete(0, uint64(len(pending)))
			slog.Error("thoth: failed to send batch", "count", len(pending), "attempts", attempt, "dropped", true)
			return
		}
		failed := map[string]bool{}
		terminal := 0
		for _, item := range output.Failed {
			if item.SenderFault {
				terminal++
			} else if item.Id != nil {
				failed[*item.Id] = true
			}
		}
		delivered := len(pending) - len(failed) - terminal
		e.delivery.complete(uint64(delivered), uint64(terminal))
		next := make([]types.SendMessageBatchRequestEntry, 0, len(failed))
		for _, entry := range pending {
			if entry.Id != nil && failed[*entry.Id] {
				next = append(next, entry)
			}
		}
		pending = next
		if len(pending) > 0 && attempt < emitterMaxAttempts {
			e.delivery.retried.Add(uint64(len(pending)))
			time.Sleep(emitterRetryDelay * time.Duration(attempt))
		}
		if len(pending) > 0 && attempt == emitterMaxAttempts {
			e.delivery.complete(0, uint64(len(pending)))
		}
	}
}

// HTTPEmitter batches BehavioralEvents and POSTs them to the hosted Thoth API.
// Emit is non-blocking; events are dropped when the buffer is full.
// Call Close() to flush remaining events and stop the background goroutine.
type HTTPEmitter struct {
	endpoint         string
	apiKey           string
	eventIngestToken string
	http             *http.Client
	ch               chan *BehavioralEvent
	wg               sync.WaitGroup
	done             chan struct{}
	closeOnce        sync.Once
	delivery         deliveryTracker
}

// NewHTTPEmitter creates an HTTPEmitter that sends events to {apiURL}/v1/events/batch
// with Bearer token authentication. Starts a background drain goroutine.
func NewHTTPEmitter(apiURL, apiKey string) *HTTPEmitter {
	return NewHTTPEmitterWithEventIngestToken(apiURL, apiKey, "")
}

// NewHTTPEmitterWithEventIngestToken creates an HTTPEmitter that sends events to
// {apiURL}/v1/events/batch with standard API-key auth headers and, optionally,
// X-Thoth-Event-Ingest-Token for dedicated ingest auth.
func NewHTTPEmitterWithEventIngestToken(apiURL, apiKey, eventIngestToken string) *HTTPEmitter {
	e := &HTTPEmitter{
		endpoint:         strings.TrimRight(apiURL, "/") + "/v1/events/batch",
		apiKey:           strings.TrimSpace(apiKey),
		eventIngestToken: strings.TrimSpace(eventIngestToken),
		http:             &http.Client{Timeout: httpEmitterTimeout},
		ch:               make(chan *BehavioralEvent, emitterBufSize),
		done:             make(chan struct{}),
	}
	e.wg.Add(1)
	go e.drainLoop()
	return e
}

// Emit enqueues an event. Non-blocking; drops the event if the buffer is full.
func (e *HTTPEmitter) Emit(event *BehavioralEvent) {
	e.delivery.pending.Add(1)
	select {
	case e.ch <- event:
	default:
		e.delivery.pending.Add(^uint64(0))
		e.delivery.dropped.Add(1)
		slog.Error("thoth: http emitter buffer full, dropping event", "event_id", event.EventID, "dropped", true)
	}
}

// Close flushes remaining events and stops the background goroutine.
func (e *HTTPEmitter) Close() {
	e.CloseWithTimeout(emitterCloseTimeout)
}

func (e *HTTPEmitter) CloseWithTimeout(timeout time.Duration) DeliveryStatus {
	e.closeOnce.Do(func() { close(e.ch) })
	select {
	case <-e.done:
	case <-time.After(timeout):
	}
	return e.Status()
}

func (e *HTTPEmitter) Status() DeliveryStatus { return e.delivery.status() }

func (e *HTTPEmitter) drainLoop() {
	defer e.wg.Done()
	defer close(e.done)
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
	projected := make([]telemetryEvent, 0, len(events))
	for _, event := range events {
		projected = append(projected, minimalTelemetryEvent(event))
	}
	payload := struct {
		Events []telemetryEvent `json:"events"`
	}{Events: projected}

	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("thoth: http emitter marshal error; events dropped", "count", len(events), "err", err, "dropped", true)
		return
	}

	for attempt := 1; attempt <= emitterMaxAttempts; attempt++ {
		req, requestErr := http.NewRequest(http.MethodPost, e.endpoint, bytes.NewReader(body))
		if requestErr != nil {
			e.delivery.complete(0, uint64(len(events)))
			slog.Error("thoth: http emitter request build error", "count", len(events), "dropped", true)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if e.apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+e.apiKey)
			req.Header.Set("X-Api-Key", e.apiKey)
		}
		if e.eventIngestToken != "" {
			req.Header.Set("X-Thoth-Event-Ingest-Token", e.eventIngestToken)
		}
		resp, sendErr := e.http.Do(req)
		if sendErr != nil {
			if attempt < emitterMaxAttempts {
				e.delivery.retried.Add(uint64(len(events)))
				time.Sleep(emitterRetryDelay * time.Duration(attempt))
				continue
			}
			e.delivery.complete(0, uint64(len(events)))
			slog.Error("thoth: http emitter send error", "count", len(events), "attempts", attempt, "dropped", true)
			return
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			_ = resp.Body.Close()
			e.delivery.complete(uint64(len(events)), 0)
			return
		}
		errBody := ""
		bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyLen))
		_ = resp.Body.Close()
		if readErr != nil {
			errBody = fmt.Sprintf("<read_error:%v>", readErr)
		} else {
			errBody = strings.TrimSpace(string(bodyBytes))
		}
		hint := ""
		if resp.StatusCode == http.StatusForbidden && strings.Contains(strings.ToLower(errBody), "<html") {
			hint = "403 HTML usually means ingress/WAF blocked telemetry before enforcer auth; exclude /v1/events* from managed body-inspection rules while keeping auth/rate/IP controls."
		}
		retryable := resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		if retryable && attempt < emitterMaxAttempts {
			e.delivery.retried.Add(uint64(len(events)))
			time.Sleep(emitterRetryDelay * time.Duration(attempt))
			continue
		}
		e.delivery.complete(0, uint64(len(events)))
		slog.Error(
			"thoth: http emitter unexpected status; events dropped",
			"status", resp.StatusCode,
			"status_text", resp.Status,
			"url", e.endpoint,
			"hint", hint,
			"count", len(events),
			"attempts", attempt,
			"dropped", true,
		)
		return
	}
}
