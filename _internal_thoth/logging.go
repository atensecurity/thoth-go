package thoth

import (
	"os"
	"strconv"
	"strings"
)

const (
	logLevelDebug = 10
	logLevelInfo  = 20
	logLevelWarn  = 30
	logLevelError = 40
)

// shouldLogDecisionDebug determines whether debug-level decision logs should be emitted.
//
// Priority: THOTH_LOG_LEVEL -> LOG_LEVEL.
// If no recognized level is configured, it returns true to preserve legacy behavior.
func shouldLogDecisionDebug() bool {
	level, ok := resolveSDKLogLevel()
	if !ok {
		return true
	}
	return level <= logLevelDebug
}

func resolveSDKLogLevel() (int, bool) {
	raw := strings.TrimSpace(os.Getenv("THOTH_LOG_LEVEL"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("LOG_LEVEL"))
	}
	if raw == "" {
		return 0, false
	}

	if numeric, err := strconv.Atoi(raw); err == nil {
		return numeric, true
	}

	switch strings.ToUpper(raw) {
	case "TRACE", "DEBUG", "NOTSET":
		return logLevelDebug, true
	case "INFO":
		return logLevelInfo, true
	case "WARN", "WARNING":
		return logLevelWarn, true
	case "ERROR", "CRITICAL", "FATAL":
		return logLevelError, true
	default:
		return 0, false
	}
}
