package thoth

import (
	"sync"

	"github.com/google/uuid"
)

// SessionContext tracks per-session state for a Thoth-instrumented agent.
// All methods are safe for concurrent use.
type SessionContext struct {
	// SessionID is the unique identifier for this session.
	SessionID string

	mu         sync.RWMutex
	toolCalls  []string
	tokenSpend int64
	config     Config
}

// NewSessionContext creates a new SessionContext with a generated UUID session ID.
func NewSessionContext(cfg Config) *SessionContext {
	return &SessionContext{
		SessionID: uuid.New().String(),
		config:    cfg,
	}
}

// RecordToolCall appends a tool name to the session's call history.
func (s *SessionContext) RecordToolCall(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.toolCalls = append(s.toolCalls, name)
}

// RecordTokenSpend adds tokens to the running total for this session.
func (s *SessionContext) RecordTokenSpend(tokens int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenSpend += tokens
}

// IsInScope reports whether toolName is in the agent's approved scope.
func (s *SessionContext) IsInScope(toolName string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, scope := range s.config.ApprovedScope {
		if scope == toolName {
			return true
		}
	}
	return false
}

// ToolCallsCopy returns an independent copy of the tool call history.
func (s *SessionContext) ToolCallsCopy() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.toolCalls) == 0 {
		return nil
	}
	out := make([]string, len(s.toolCalls))
	copy(out, s.toolCalls)
	return out
}

// TokenSpend returns the cumulative token spend for this session.
func (s *SessionContext) TokenSpend() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tokenSpend
}
