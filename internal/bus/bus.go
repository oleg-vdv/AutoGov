// Package bus is the event bus of the control plane (ТЗ §4.2).
//
// Agents publish raw observations, modules consume them and publish findings.
// The bus decouples collection from analysis and is the extension point for
// M2–M4 (ТЗ-0): a new module only subscribes to event types, the core does
// not change.
package bus

import (
	"context"
	"log/slog"
	"strings"
	"sync"

	"github.com/oleg-vdv/autogov/internal/model"
)

// Handler processes one event. Handlers must not block for long.
type Handler func(ctx context.Context, ev model.Event)

type subscription struct {
	pattern string // exact type or prefix glob "observation.*" or "*"
	handler Handler
}

// Bus is an in-process pub/sub with a single ordered dispatch loop.
// Ordering is deterministic which keeps module logic simple; throughput is
// sufficient for the MVP scale target (~10k instances, ТЗ §8.1).
type Bus struct {
	mu     sync.RWMutex
	subs   []subscription
	queue  chan model.Event
	done   chan struct{}
	logger *slog.Logger
}

// New creates a bus with the given queue capacity.
func New(capacity int, logger *slog.Logger) *Bus {
	if capacity <= 0 {
		capacity = 4096
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Bus{
		queue:  make(chan model.Event, capacity),
		done:   make(chan struct{}),
		logger: logger,
	}
}

// Subscribe registers a handler for an event type pattern.
// Patterns: exact ("finding.created"), prefix ("observation.*"), or "*".
func (b *Bus) Subscribe(pattern string, h Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subs = append(b.subs, subscription{pattern: pattern, handler: h})
}

// Publish enqueues an event. Non-blocking; drops with a log record when the
// queue is full (agents buffer and resend, ТЗ §8.2).
func (b *Bus) Publish(ev model.Event) {
	select {
	case b.queue <- ev:
	default:
		b.logger.Warn("event bus queue full, dropping event", "type", ev.Type, "id", ev.ID)
	}
}

// Run dispatches events until ctx is cancelled.
func (b *Bus) Run(ctx context.Context) {
	defer close(b.done)
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-b.queue:
			b.dispatch(ctx, ev)
		}
	}
}

// Drain waits for the dispatch loop to stop (after ctx cancellation).
func (b *Bus) Drain() { <-b.done }

func (b *Bus) dispatch(ctx context.Context, ev model.Event) {
	b.mu.RLock()
	subs := make([]subscription, len(b.subs))
	copy(subs, b.subs)
	b.mu.RUnlock()
	for _, s := range subs {
		if Match(s.pattern, ev.Type) {
			s.handler(ctx, ev)
		}
	}
}

// Match reports whether an event type matches a subscription pattern.
func Match(pattern, eventType string) bool {
	if pattern == "*" || pattern == eventType {
		return true
	}
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(eventType, prefix)
	}
	return false
}
