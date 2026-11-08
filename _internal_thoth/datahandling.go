package thoth

// Drop, redact or hash values at the source, before a request leaves the process.
//
// Opt-in per client. With nothing configured this file changes nothing.
//
// Tool arguments (Config.DataHandlingToolArguments or
// THOTH_DATA_HANDLING_TOOL_ARGUMENTS):
//
//	hash    keys and structure are kept; every leaf (string, number, boolean)
//	        becomes "hmac-sha256:" + hex(HMAC-SHA256(salt, canonical_json(leaf))).
//	        null stays null.
//	redact  keys and structure are kept; every leaf, null included, becomes "<redacted>".
//	drop    no arguments are sent: the tool_args field is omitted.
//
// Prompts (Config.DataHandlingPrompts or THOTH_DATA_HANDLING_PROMPTS):
//
//	hash    a prompt-bearing field is replaced by one hash of its whole value.
//	drop    the field is omitted.
//
// The salt is held by the client and never sent. It comes from the option,
// else THOTH_DATA_HANDLING_SALT, else a random per-process salt. Nested
// arguments are walked to depth 16 and at most 5,000 values; anything past
// that becomes "<truncated>", so no original value passes untransformed.
//
// The golden fixture testdata/sdk/data_handling_golden.json pins these formats
// so every Thoth SDK produces the same bytes.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	// DataHandlingVersion is the version declared in the request's data_handling field.
	DataHandlingVersion = 1

	RedactedMarker  = "<redacted>"
	TruncatedMarker = "<truncated>"
	HashPrefix      = "hmac-sha256:"
	// MaxDepth and MaxNodes bound the walk over nested arguments.
	MaxDepth = 16
	MaxNodes = 5000
	// LongTextChars: a string longer than this inside a context map counts as free text.
	LongTextChars = 512

	EnvToolArguments = "THOTH_DATA_HANDLING_TOOL_ARGUMENTS"
	EnvPrompts       = "THOTH_DATA_HANDLING_PROMPTS"
	EnvSalt          = "THOTH_DATA_HANDLING_SALT"
	EnvLocalScan     = "THOTH_DATA_HANDLING_LOCAL_SCAN"

	ModeHash   = "hash"
	ModeRedact = "redact"
	ModeDrop   = "drop"
)

// promptKeys: values under these key names, at any depth of a context map, are
// model or user text and get the prompts mode. Spelling-insensitive:
// User_Message and user-message match usermessage.
var promptKeys = map[string]struct{}{
	"prompt": {}, "prompts": {}, "systemprompt": {}, "userprompt": {}, "usermessage": {},
	"message": {}, "messages": {}, "input": {}, "inputtext": {}, "query": {}, "question": {},
	"text": {}, "content": {}, "instruction": {}, "instructions": {}, "task": {}, "goal": {},
	"description": {}, "summary": {}, "note": {}, "notes": {}, "comment": {},
	"conversation": {}, "conversationcontext": {}, "conversationinputtext": {},
	"conversationoutputtext": {}, "history": {}, "transcript": {}, "completion": {},
	"response": {}, "output": {}, "toolresult": {}, "tooloutput": {},
}

var (
	processSaltOnce  sync.Once
	processSaltValue string
)

// ProcessSalt is the random salt shared by every client in this process, made once.
func ProcessSalt() string {
	processSaltOnce.Do(func() {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			// crypto/rand does not fail on supported platforms; never fall back to a guessable salt.
			panic("thoth: no random source for the data handling salt")
		}
		processSaltValue = hex.EncodeToString(raw)
	})
	return processSaltValue
}

func sha256Hex(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func blank(s string) bool { return strings.TrimSpace(s) == "" }

func normalizeMode(value string, allowed []string, name string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(value))
	if mode == "" {
		return "", nil
	}
	for _, ok := range allowed {
		if mode == ok {
			return mode, nil
		}
	}
	return "", fmt.Errorf("thoth: %s must be one of %s; got %q. Thoth will not send the values unprotected, so fix the setting",
		name, strings.Join(allowed, ", "), value)
}

// ResolveToolArgumentsMode is the configured mode: option, else environment,
// validated. Empty when unset; an invalid value is an error.
func ResolveToolArgumentsMode(option string) (string, error) {
	if blank(option) {
		return normalizeMode(os.Getenv(EnvToolArguments), []string{ModeHash, ModeRedact, ModeDrop}, EnvToolArguments)
	}
	return normalizeMode(option, []string{ModeHash, ModeRedact, ModeDrop}, "DataHandlingToolArguments")
}

// ResolvePromptsMode is the configured prompts mode: option, else environment.
func ResolvePromptsMode(option string) (string, error) {
	if blank(option) {
		return normalizeMode(os.Getenv(EnvPrompts), []string{ModeHash, ModeDrop}, EnvPrompts)
	}
	return normalizeMode(option, []string{ModeHash, ModeDrop}, "DataHandlingPrompts")
}

// ResolveSalt is the configured salt (option, else environment); empty means use
// the per-process salt.
func ResolveSalt(option string) string {
	chosen := option
	if blank(chosen) {
		chosen = os.Getenv(EnvSalt)
	}
	if blank(chosen) {
		return ""
	}
	return chosen
}

// ResolveLocalScan reports whether to scan withheld arguments locally: option,
// else environment, default on. An unclear value is an error.
func ResolveLocalScan(option string) (bool, error) {
	chosen, name := option, "DataHandlingLocalScan"
	if blank(chosen) {
		chosen, name = os.Getenv(EnvLocalScan), EnvLocalScan
	}
	switch strings.ToLower(strings.TrimSpace(chosen)) {
	case "", "on", "true", "1", "yes":
		return true, nil
	case "off", "false", "0", "no":
		return false, nil
	}
	return false, fmt.Errorf("thoth: %s must be on or off; got %q", name, chosen)
}

// HashValue is "hmac-sha256:" + hex of HMAC-SHA256(salt, canonical JSON of value).
func HashValue(salt string, value any) string {
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(canonicalJSON(value)))
	return HashPrefix + hex.EncodeToString(mac.Sum(nil))
}

type budget struct{ remaining int }

// mapLeaves copies a value with every leaf passed through leaf. Containers are
// rebuilt, so the input is never modified.
func mapLeaves(value any, leaf func(node) any, b *budget, depth int) any {
	if b.remaining <= 0 || depth > MaxDepth {
		return TruncatedMarker
	}
	b.remaining--
	n := classify(value)
	switch n.kind {
	case kindObject:
		out := make(map[string]any, len(n.obj))
		for _, item := range n.obj {
			if b.remaining <= 0 {
				out["_truncated"] = TruncatedMarker
				break
			}
			out[item.key] = mapLeaves(item.value, leaf, b, depth+1)
		}
		return out
	case kindList:
		items := make([]any, 0, len(n.list))
		for _, item := range n.list {
			if b.remaining <= 0 {
				items = append(items, TruncatedMarker)
				break
			}
			items = append(items, mapLeaves(item, leaf, b, depth+1))
		}
		return items
	}
	return leaf(n)
}

// RedactArguments keeps structure and keys and replaces every leaf with "<redacted>".
func RedactArguments(value any) any {
	return mapLeaves(value, func(node) any { return RedactedMarker }, &budget{MaxNodes}, 0)
}

// HashArguments keeps structure and keys and replaces every leaf but null with its keyed hash.
func HashArguments(value any, salt string) any {
	return mapLeaves(value, func(n node) any {
		if n.kind == kindNull {
			return nil
		}
		return hashNode(salt, n)
	}, &budget{MaxNodes}, 0)
}

func hashNode(salt string, n node) string {
	mac := hmac.New(sha256.New, []byte(salt))
	var sb strings.Builder
	switch n.kind {
	case kindBool, kindNumber:
		sb.WriteString(n.text)
	default:
		writeJSONString(&sb, n.text)
	}
	mac.Write([]byte(sb.String()))
	return HashPrefix + hex.EncodeToString(mac.Sum(nil))
}

// TransformArguments returns (keep, new value) for tool arguments under mode.
func TransformArguments(value any, mode, salt string) (bool, any) {
	switch mode {
	case ModeDrop:
		return false, nil
	case ModeRedact:
		return true, RedactArguments(value)
	case ModeHash:
		return true, HashArguments(value, salt)
	}
	panic("thoth: unknown tool arguments mode " + mode)
}

// TransformPrompt returns (keep, new value) for a prompt-bearing value under mode.
func TransformPrompt(value any, mode, salt string) (bool, any) {
	switch mode {
	case ModeDrop:
		return false, nil
	case ModeHash:
		if classify(value).kind == kindNull {
			return true, nil
		}
		return true, HashValue(salt, value)
	}
	panic("thoth: unknown prompts mode " + mode)
}

func normalizedKey(key string) string {
	return strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(key))
}

// walkContext is a copy of a context value with prompt-bearing and long
// free-text values handled.
func walkContext(value any, mode, salt string, depth int) any {
	if depth > MaxDepth {
		return TruncatedMarker
	}
	n := classify(value)
	switch n.kind {
	case kindObject:
		out := make(map[string]any, len(n.obj))
		for _, item := range n.obj {
			if _, ok := promptKeys[normalizedKey(item.key)]; ok {
				if keep, next := TransformPrompt(item.value, mode, salt); keep {
					out[item.key] = next
				}
				continue
			}
			out[item.key] = walkContext(item.value, mode, salt, depth+1)
		}
		return out
	case kindList:
		items := make([]any, len(n.list))
		for i, item := range n.list {
			items[i] = walkContext(item, mode, salt, depth+1)
		}
		return items
	case kindString:
		if utf8.RuneCountInString(n.text) > LongTextChars {
			// Free text under an unremarkable key cannot be omitted from a list
			// or a value position without changing structure, so it is hashed
			// or replaced by the redaction marker.
			if mode == ModeHash {
				return HashValue(salt, n.text)
			}
			return RedactedMarker
		}
	}
	return value
}

// TransformContext copies a context map with prompt-bearing and long free-text values handled.
func TransformContext(value map[string]any, mode, salt string) map[string]any {
	out, _ := walkContext(value, mode, salt, 0).(map[string]any)
	return out
}

// DataHandling is what a client applies before sending. Immutable; safe to
// share across goroutines.
type DataHandling struct {
	ToolArguments string
	Prompts       string
	Salt          string
	// LocalScan: with tool arguments withheld, scan the raw arguments in this
	// process and send client_findings. On unless switched off.
	LocalScan bool
}

// ResolveDataHandling reads the options, else the environment. It returns nil
// when nothing is configured and an error for an invalid value, so a
// misspelled mode never falls back to sending values unprotected.
func ResolveDataHandling(toolArguments, prompts, salt, localScan string) (*DataHandling, error) {
	argsMode, err := ResolveToolArgumentsMode(toolArguments)
	if err != nil {
		return nil, err
	}
	promptMode, err := ResolvePromptsMode(prompts)
	if err != nil {
		return nil, err
	}
	scan, err := ResolveLocalScan(localScan)
	if err != nil {
		return nil, err
	}
	if argsMode == "" && promptMode == "" {
		return nil, nil
	}
	chosenSalt := ResolveSalt(salt)
	if chosenSalt == "" {
		chosenSalt = ProcessSalt()
	}
	return &DataHandling{ToolArguments: argsMode, Prompts: promptMode, Salt: chosenSalt, LocalScan: scan}, nil
}

// ArgumentsWithheld reports whether tool-argument values are withheld from Thoth.
func (d *DataHandling) ArgumentsWithheld() bool {
	return d != nil && d.ToolArguments != ""
}

// ScansLocally reports whether a client_findings report is built.
func (d *DataHandling) ScansLocally() bool {
	return d.ArgumentsWithheld() && d.LocalScan
}

// Declaration is the data_handling field of the request, naming only what was applied.
func (d *DataHandling) Declaration() map[string]any {
	out := map[string]any{"applied_at": "client", "version": DataHandlingVersion}
	if d.ToolArguments != "" {
		out["tool_arguments"] = d.ToolArguments
	}
	if d.Prompts != "" {
		out["prompts"] = d.Prompts
	}
	return out
}

// transformContextField copies a context map with the prompts mode applied.
// Empty maps are left as they are.
func (d *DataHandling) transformContextField(field map[string]any) map[string]any {
	if d.Prompts == "" || len(field) == 0 {
		return field
	}
	return TransformContext(field, d.Prompts, d.Salt)
}
