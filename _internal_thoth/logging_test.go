package thoth

import "testing"

func TestShouldLogDecisionDebug_DefaultTrue(t *testing.T) {
	t.Setenv("THOTH_LOG_LEVEL", "")
	t.Setenv("LOG_LEVEL", "")

	if !shouldLogDecisionDebug() {
		t.Fatal("expected debug decision logs to remain enabled by default")
	}
}

func TestShouldLogDecisionDebug_THOTHLogLevelHasPriority(t *testing.T) {
	t.Setenv("THOTH_LOG_LEVEL", "INFO")
	t.Setenv("LOG_LEVEL", "DEBUG")

	if shouldLogDecisionDebug() {
		t.Fatal("expected THOTH_LOG_LEVEL=INFO to suppress debug decision logs")
	}
}

func TestShouldLogDecisionDebug_UsesLogLevelFallback(t *testing.T) {
	t.Setenv("THOTH_LOG_LEVEL", "")
	t.Setenv("LOG_LEVEL", "DEBUG")

	if !shouldLogDecisionDebug() {
		t.Fatal("expected LOG_LEVEL=DEBUG fallback to enable debug decision logs")
	}
}

func TestShouldLogDecisionDebug_RecognizesWarning(t *testing.T) {
	t.Setenv("THOTH_LOG_LEVEL", "warning")
	t.Setenv("LOG_LEVEL", "")

	if shouldLogDecisionDebug() {
		t.Fatal("expected warning level to suppress debug decision logs")
	}
}
