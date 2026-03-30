package thoth_test

import (
	"sync"
	"testing"

	"github.com/atensecurity/thoth-go/_internal_thoth"
)

func TestSessionContext_RecordToolCall(t *testing.T) {
	t.Parallel()
	cfg := thoth.Config{
		AgentID:       "agent-1",
		TenantID:      "tenant-1",
		ApprovedScope: []string{"read:invoices", "write:slack"},
	}
	s := thoth.NewSessionContext(cfg)
	if s.SessionID == "" {
		t.Fatal("SessionID must be set")
	}

	s.RecordToolCall("read:invoices")
	s.RecordToolCall("write:slack")

	calls := s.ToolCallsCopy()
	if len(calls) != 2 {
		t.Fatalf("expected 2 tool calls, got %d", len(calls))
	}
	if calls[0] != "read:invoices" || calls[1] != "write:slack" {
		t.Errorf("unexpected tool calls: %v", calls)
	}
}

func TestSessionContext_ToolCallsCopy_IsACopy(t *testing.T) {
	t.Parallel()
	cfg := thoth.Config{AgentID: "a", TenantID: "t", ApprovedScope: []string{"tool1"}}
	s := thoth.NewSessionContext(cfg)
	s.RecordToolCall("tool1")

	copy1 := s.ToolCallsCopy()
	copy1[0] = "mutated"

	copy2 := s.ToolCallsCopy()
	if copy2[0] == "mutated" {
		t.Error("ToolCallsCopy should return an independent copy")
	}
}

func TestSessionContext_RecordTokenSpend(t *testing.T) {
	t.Parallel()
	cfg := thoth.Config{AgentID: "a", TenantID: "t"}
	s := thoth.NewSessionContext(cfg)

	s.RecordTokenSpend(100)
	s.RecordTokenSpend(250)

	if s.TokenSpend() != 350 {
		t.Errorf("TokenSpend() = %d, want 350", s.TokenSpend())
	}
}

func TestSessionContext_IsInScope(t *testing.T) {
	t.Parallel()
	cfg := thoth.Config{
		AgentID:       "a",
		TenantID:      "t",
		ApprovedScope: []string{"read:invoices", "write:slack"},
	}
	s := thoth.NewSessionContext(cfg)

	cases := []struct {
		tool string
		want bool
	}{
		{"read:invoices", true},
		{"write:slack", true},
		{"delete:db", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			t.Parallel()
			if got := s.IsInScope(tc.tool); got != tc.want {
				t.Errorf("IsInScope(%q) = %v, want %v", tc.tool, got, tc.want)
			}
		})
	}
}

func TestSessionContext_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	cfg := thoth.Config{
		AgentID:       "a",
		TenantID:      "t",
		ApprovedScope: []string{"tool"},
	}
	s := thoth.NewSessionContext(cfg)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			s.RecordToolCall("tool")
		}()
		go func() {
			defer wg.Done()
			s.RecordTokenSpend(1)
		}()
		go func() {
			defer wg.Done()
			_ = s.ToolCallsCopy()
		}()
	}
	wg.Wait()

	if got := s.TokenSpend(); got != int64(goroutines) {
		t.Errorf("TokenSpend() = %d, want %d", got, goroutines)
	}
	if got := len(s.ToolCallsCopy()); got != goroutines {
		t.Errorf("tool call count = %d, want %d", got, goroutines)
	}
}

func TestNewSessionContext_GeneratesUniqueIDs(t *testing.T) {
	t.Parallel()
	cfg := thoth.Config{AgentID: "a", TenantID: "t"}
	s1 := thoth.NewSessionContext(cfg)
	s2 := thoth.NewSessionContext(cfg)
	if s1.SessionID == s2.SessionID {
		t.Error("SessionIDs should be unique")
	}
}
