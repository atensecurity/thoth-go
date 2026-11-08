package thoth

// Scan tool arguments on this side and report what was found, never the values.
//
// When tool-argument values are withheld (see datahandling.go), Thoth cannot
// look at them. This file scans the raw arguments in your process first and
// builds the client_findings field of the request: counts, categories,
// hostnames and recipient domains. It implements the shared detector spec
// (detectors.v1.json, embedded next to this file; docs/integrations/
// local-scan-detectors.md in the monorepo explains it) independently in Go.
//
// The detectors are heuristic regular expressions. A finding is a signal, not
// proof that data is sensitive, and no finding is not proof that it is not.
// This is not a compliance statement of any kind.
//
// What leaves the process: counts, categories, hostnames and recipient
// domains. Never values, paths, local parts of addresses, display names or
// message text.
//
// Trust is the workspace's call. Thoth cannot verify a client scan; it relies
// on one only when the workspace opted in and listed this ruleset's hash.
// Findings only ever raise a decision.
//
// Failing closed: a check that cannot be completed (a node bound was hit, the
// check panicked, the report would not fit) is left out of "scanned" and has no
// findings, so Thoth sees it as missing rather than clean.
//
// Go's regexp package is RE2: \b, \w and \d are ASCII, as the spec requires.
// Its \s lacks the vertical tab, so every \s in a spec pattern is rewritten to
// the spec's ASCII whitespace class before compiling. Case-insensitive
// matching uses Unicode simple folding (as Python's does): K (U+212A) and
// the long s (U+017F) match k and s. That can only count more than an ASCII
// engine, never less. No net/url: hosts are extracted by the spec's own steps.

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"unicode/utf8"
)

// ScannerName is what the report identifies itself as. The server accepts
// [A-Za-z0-9][A-Za-z0-9._-]{0,63}, so the module path cannot be used.
const ScannerName = "atensec-thoth-go"

// ReportVersion is the client_findings schema version.
const ReportVersion = 1

const (
	asciiSpaceClass = ` \t\n\v\f\r`
	// unparsed stands for a recipient that could not be read; it never matches an address.
	unparsed  = "<unparsed>"
	maxDomain = 253
	maxLabel  = 63
	// A bound on the version text the server accepts.
	maxVersionChars = 32
)

//go:embed detectors.v1.json
var embeddedSpec []byte

// EmbeddedDetectorSpec returns a copy of the detector spec compiled into the SDK.
func EmbeddedDetectorSpec() []byte {
	return append([]byte(nil), embeddedSpec...)
}

// ErrLocalScan means the detector spec could not be loaded or does not match its pinned hash.
var ErrLocalScan = errors.New("thoth: local scan: detector spec does not match its ruleset_hash")

type patternSpec struct {
	Pattern string   `json:"pattern"`
	Flags   []string `json:"flags"`
}

type detectorSpec struct {
	RulesetID   string `json:"ruleset_id"`
	RulesetHash string `json:"ruleset_hash"`
	Detectors   struct {
		Bounds struct {
			MaxDepth        int `json:"max_depth"`
			MaxValues       int `json:"max_values"`
			MaxCount        int `json:"max_count"`
			MaxFindings     int `json:"max_findings"`
			MaxPayloadBytes int `json:"max_payload_bytes"`
		} `json:"bounds"`
		DLP struct {
			Categories []string `json:"categories"`
			Steps      []struct {
				ID          string   `json:"id"`
				Category    string   `json:"category"`
				Pattern     string   `json:"pattern"`
				Flags       []string `json:"flags"`
				Replacement string   `json:"replacement"`
			} `json:"steps"`
		} `json:"dlp"`
		SensitivePath struct {
			Keys []string `json:"keys"`
			patternSpec
		} `json:"sensitive_path"`
		EgressHost struct {
			Sources []struct {
				From            string   `json:"from"`
				Key             string   `json:"key"`
				FirstNonEmptyOf []string `json:"first_non_empty_of"`
			} `json:"sources"`
			HostGrammar struct {
				patternSpec
				MaxLength int `json:"max_length"`
			} `json:"host_grammar"`
		} `json:"egress_host"`
		Recipient struct {
			Fields                     []string    `json:"fields"`
			ExtraFieldsForSendingTools []string    `json:"extra_fields_for_sending_tools"`
			SendingToolPattern         patternSpec `json:"sending_tool_pattern"`
			PositionalKeys             patternSpec `json:"positional_keys"`
			DataMove                   struct {
				ToolNameHint patternSpec `json:"tool_name_hint"`
				Fields       []string    `json:"fields"`
			} `json:"data_move"`
			Address               patternSpec `json:"address"`
			TextDomainPattern     patternSpec `json:"text_domain_pattern"`
			MaxDomains            int         `json:"max_domains"`
			MaxUnresolvedFindings int         `json:"max_unresolved_findings"`
		} `json:"recipient"`
		Report struct {
			ScannedOrder []string `json:"scanned_order"`
		} `json:"report"`
	} `json:"detectors"`
}

// ComputeRulesetHash is the sha256 hex of the canonical "detectors" object, as
// the spec's hash_rule defines. It fails when the spec is not valid JSON.
func ComputeRulesetHash(spec []byte) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(spec))
	decoder.UseNumber()
	var doc map[string]any
	if err := decoder.Decode(&doc); err != nil {
		return "", err
	}
	detectors, ok := doc["detectors"]
	if !ok {
		return "", errors.New("thoth: local scan: spec has no detectors")
	}
	return sha256Hex(canonicalJSON(detectors)), nil
}

type dlpStep struct {
	category    string
	regex       *regexp.Regexp
	replacement string
}

// LocalScanner is built from the spec. Immutable and safe for concurrent use.
type LocalScanner struct {
	RulesetID   string
	RulesetHash string
	Version     string
	// MaxBytes is settable only so tests can exercise the size bound with a smaller limit.
	MaxBytes int

	spec         detectorSpec
	steps        []dlpStep
	pathRegex    *regexp.Regexp
	hostRegex    *regexp.Regexp
	hostMax      int
	fields       map[string]struct{}
	extraFields  map[string]struct{}
	sending      *regexp.Regexp
	moveTool     *regexp.Regexp
	moveFields   map[string]struct{}
	positional   *regexp.Regexp
	address      *regexp.Regexp
	textDomain   *regexp.Regexp
	bracketed    *regexp.Regexp
	maxDepth     int
	maxValues    int
	maxCount     int
	maxFindings  int
	scannedOrder []string
	// panicHook lets tests make one check panic; nil in production.
	panicHook func(check string)
}

// asciiSpace rewrites \s (and \S outside a class) to the spec's ASCII class.
func asciiSpace(pattern string) (string, error) {
	var out strings.Builder
	inClass := false
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		if ch == '\\' && i+1 < len(pattern) {
			next := pattern[i+1]
			switch {
			case next == 's' && inClass:
				out.WriteString(asciiSpaceClass)
			case next == 's':
				out.WriteString("[" + asciiSpaceClass + "]")
			case next == 'S' && inClass:
				return "", fmt.Errorf("thoth: local scan: \\S inside a class is not supported (pattern %q)", pattern)
			case next == 'S':
				out.WriteString("[^" + asciiSpaceClass + "]")
			default:
				out.WriteByte(ch)
				out.WriteByte(next)
			}
			i++
			continue
		}
		if ch == '[' && !inClass {
			inClass = true
		} else if ch == ']' && inClass {
			inClass = false
		}
		out.WriteByte(ch)
	}
	return out.String(), nil
}

func compilePattern(pattern string, flags []string) (*regexp.Regexp, error) {
	for _, flag := range flags {
		if flag != "i" {
			return nil, fmt.Errorf("thoth: local scan: unsupported regex flag %q", flag)
		}
	}
	rewritten, err := asciiSpace(pattern)
	if err != nil {
		return nil, err
	}
	// Go has no option for case-insensitivity other than the inline flag.
	for _, flag := range flags {
		if flag == "i" {
			rewritten = "(?i)" + rewritten
		}
	}
	return regexp.Compile(rewritten)
}

func set(items []string) map[string]struct{} {
	out := make(map[string]struct{}, len(items))
	for _, item := range items {
		out[item] = struct{}{}
	}
	return out
}

// sdkVersion is the version of the thoth-go module in the build, cleaned to
// what the server accepts, or "0" when the build does not say (tests, a
// checkout, a vendored copy).
func sdkVersion() string {
	raw := "0"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/atensecurity/thoth-go" {
				raw = dep.Version
				if dep.Replace != nil && dep.Replace.Version != "" {
					raw = dep.Replace.Version
				}
			}
		}
		if info.Main.Path == "github.com/atensecurity/thoth-go" {
			raw = info.Main.Version
		}
	}
	return cleanVersion(raw)
}

func cleanVersion(raw string) string {
	var sb strings.Builder
	for _, r := range raw {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '+', r == '-':
			sb.WriteRune(r)
		}
	}
	cleaned := sb.String()
	if len(cleaned) > maxVersionChars {
		cleaned = cleaned[:maxVersionChars]
	}
	cleaned = strings.TrimLeft(cleaned, "._+-")
	// "v0.1.22" is the module's spelling of 0.1.22.
	if len(cleaned) > 1 && cleaned[0] == 'v' && cleaned[1] >= '0' && cleaned[1] <= '9' {
		cleaned = cleaned[1:]
	}
	if cleaned == "" || cleaned == "devel" {
		return "0"
	}
	return cleaned
}

// NewLocalScanner builds a scanner from a spec document. It refuses a spec
// whose ruleset_hash is not the hash of its own detectors. An empty version
// means the SDK's.
func NewLocalScanner(specJSON []byte, version string) (*LocalScanner, error) {
	actual, err := ComputeRulesetHash(specJSON)
	if err != nil {
		return nil, err
	}
	var spec detectorSpec
	if err := json.Unmarshal(specJSON, &spec); err != nil {
		return nil, err
	}
	if spec.RulesetHash != actual {
		return nil, ErrLocalScan
	}
	if version == "" {
		version = sdkVersion()
	}
	d := &spec.Detectors
	s := &LocalScanner{
		RulesetID:    spec.RulesetID,
		RulesetHash:  actual,
		Version:      version,
		MaxBytes:     d.Bounds.MaxPayloadBytes,
		spec:         spec,
		maxDepth:     d.Bounds.MaxDepth,
		maxValues:    d.Bounds.MaxValues,
		maxCount:     d.Bounds.MaxCount,
		maxFindings:  d.Bounds.MaxFindings,
		scannedOrder: d.Report.ScannedOrder,
		hostMax:      d.EgressHost.HostGrammar.MaxLength,
		fields:       set(d.Recipient.Fields),
		extraFields:  set(d.Recipient.ExtraFieldsForSendingTools),
		moveFields:   set(d.Recipient.DataMove.Fields),
	}
	for _, step := range d.DLP.Steps {
		regex, err := compilePattern(step.Pattern, step.Flags)
		if err != nil {
			return nil, err
		}
		s.steps = append(s.steps, dlpStep{step.Category, regex, step.Replacement})
	}
	compile := func(target **regexp.Regexp, p patternSpec) error {
		regex, err := compilePattern(p.Pattern, p.Flags)
		if err != nil {
			return err
		}
		*target = regex
		return nil
	}
	for _, job := range []struct {
		target **regexp.Regexp
		spec   patternSpec
	}{
		{&s.pathRegex, d.SensitivePath.patternSpec},
		{&s.hostRegex, d.EgressHost.HostGrammar.patternSpec},
		{&s.sending, d.Recipient.SendingToolPattern},
		{&s.moveTool, d.Recipient.DataMove.ToolNameHint},
		{&s.positional, d.Recipient.PositionalKeys},
		{&s.address, d.Recipient.Address},
	} {
		if err := compile(job.target, job.spec); err != nil {
			return nil, err
		}
	}
	// Matched directly after an '@' (the text rule), so it is anchored.
	textDomain, err := compilePattern("^(?:"+d.Recipient.TextDomainPattern.Pattern+")", d.Recipient.TextDomainPattern.Flags)
	if err != nil {
		return nil, err
	}
	s.textDomain = textDomain
	s.bracketed = regexp.MustCompile(`<([^<>]*)>`)
	return s, nil
}

// ---------------------------------------------------------------------------
// Characters
// ---------------------------------------------------------------------------

// isPythonSpace is what Python's str.isspace() treats as whitespace: the
// spec's "any whitespace character" and the 23 characters of
// detectors.recipient.ambiguous_input clause (d) on top of ASCII whitespace.
func isPythonSpace(r rune) bool {
	switch {
	case r >= 0x09 && r <= 0x0d, r >= 0x1c && r <= 0x20:
		return true
	case r == 0x85, r == 0xa0, r == 0x1680, r >= 0x2000 && r <= 0x200a:
		return true
	case r == 0x2028, r == 0x2029, r == 0x202f, r == 0x205f, r == 0x3000:
		return true
	}
	return false
}

// isOnlyPythonSpace: the 23 characters Python splits and strips on and an
// ASCII engine does not (clause d).
func isOnlyPythonSpace(r rune) bool {
	return isPythonSpace(r) && !isASCIISpace(r)
}

func isASCIISpace(r rune) bool {
	return r == ' ' || (r >= 0x09 && r <= 0x0d)
}

func hasOnlyPythonSpace(text string) bool {
	for _, r := range text {
		if isOnlyPythonSpace(r) {
			return true
		}
	}
	return false
}

// plain: printable ASCII and ASCII whitespace only (detectors.recipient.ambiguous_input).
func plain(text string) bool {
	for _, r := range text {
		if !((r >= 0x20 && r <= 0x7e) || (r >= 0x09 && r <= 0x0d)) {
			return false
		}
	}
	return true
}

func blankString(text string) bool {
	for _, r := range text {
		if !isPythonSpace(r) {
			return false
		}
	}
	return true
}

func asciiTrim(text string) string {
	return strings.TrimFunc(text, isASCIISpace)
}

func words(text string) []string {
	return strings.FieldsFunc(text, isASCIISpace)
}

// pyLower lower-cases as Python's str.lower() and JavaScript's toLowerCase()
// do. Go's simple mapping turns U+0130 into "i", where they write "i" and
// U+0307; a host must not become valid that way.
func pyLower(text string) string {
	return strings.ToLower(strings.ReplaceAll(text, "İ", "i̇"))
}

func normalKey(key string) string {
	var sb strings.Builder
	for _, r := range key {
		if r == '_' || r == '-' || isPythonSpace(r) {
			continue
		}
		sb.WriteRune(r)
	}
	return pyLower(sb.String())
}

// ---------------------------------------------------------------------------
// Bounded traversal
// ---------------------------------------------------------------------------

// A scan tree is nil, string, other{}, []any or object. Anything the scan
// does not read as text (numbers, booleans, values with no JSON form) is other{}.
type (
	other  struct{}
	object []entry
)

// bounded copies the arguments into a scan tree under the spec's bounds: the
// root is depth 0, nodes deeper than max_depth are not visited, every visited
// node costs one of max_values, pre-order. truncated is true when any node was
// left unvisited.
func (s *LocalScanner) bounded(root any) (tree any, truncated bool) {
	left := s.maxValues
	var visit func(v any, depth int) any
	visit = func(v any, depth int) any {
		if depth > s.maxDepth || left <= 0 {
			truncated = true
			return nil
		}
		left--
		n := classify(v)
		switch n.kind {
		case kindObject:
			out := make(object, 0, len(n.obj))
			for _, item := range n.obj {
				out = append(out, entry{item.key, visit(item.value, depth+1)})
			}
			return out
		case kindList:
			out := make([]any, 0, len(n.list))
			for _, item := range n.list {
				out = append(out, visit(item, depth+1))
			}
			return out
		case kindString:
			return n.text
		case kindNull:
			return nil
		}
		return other{}
	}
	return visit(root, 0), truncated
}

func leavesOf(tree any, out *[]string) {
	switch x := tree.(type) {
	case string:
		*out = append(*out, x)
	case []any:
		for _, item := range x {
			leavesOf(item, out)
		}
	case object:
		for _, item := range x {
			leavesOf(item.value, out)
		}
	}
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

func (s *LocalScanner) dlp(leaves []string) []map[string]any {
	counts := map[string]int{}
	for _, leaf := range leaves {
		text := leaf
		for _, step := range s.steps {
			matches := step.regex.FindAllStringSubmatchIndex(text, -1)
			if len(matches) == 0 {
				continue
			}
			counts[step.category] += len(matches)
			var out strings.Builder
			last := 0
			for _, m := range matches {
				out.WriteString(text[last:m[0]])
				group := ""
				if len(m) >= 4 && m[2] >= 0 {
					group = text[m[2]:m[3]]
				}
				// The replacement is literal text: no group or backslash escapes.
				out.WriteString(strings.ReplaceAll(step.replacement, "{group1}", group))
				last = m[1]
			}
			out.WriteString(text[last:])
			text = out.String()
		}
	}
	var findings []map[string]any
	for _, category := range s.spec.Detectors.DLP.Categories {
		if counts[category] > 0 {
			findings = append(findings, map[string]any{"kind": "dlp", "category": category, "count": min(counts[category], s.maxCount)})
		}
	}
	return findings
}

func objectGet(root any, key string) (any, bool) {
	n := classify(root)
	if n.kind != kindObject {
		return nil, false
	}
	for _, item := range n.obj {
		if item.key == key {
			return item.value, true
		}
	}
	return nil, false
}

func (s *LocalScanner) sensitivePath(args any) []map[string]any {
	var candidates []string
	keys := s.spec.Detectors.SensitivePath.Keys
	if one, ok := objectGet(args, keys[0]); ok {
		if n := classify(one); n.kind == kindString && n.text != "" {
			candidates = append(candidates, n.text)
		}
	}
	if many, ok := objectGet(args, keys[1]); ok {
		if n := classify(many); n.kind == kindList {
			for _, item := range n.list {
				if m := classify(item); m.kind == kindString && m.text != "" {
					candidates = append(candidates, m.text)
				}
			}
		}
	}
	count := 0
	for _, candidate := range candidates {
		if s.pathRegex.MatchString(candidate) {
			count++
		}
	}
	if count == 0 {
		return nil
	}
	return []map[string]any{{"kind": "sensitive_path", "count": min(count, s.maxCount)}}
}

// firstString is the first value under keys that is a string non-empty after trimming.
func firstString(source any, keys []string) (string, bool) {
	n := classify(source)
	if n.kind != kindObject {
		return "", false
	}
	for _, key := range keys {
		for _, item := range n.obj {
			if item.key != key {
				continue
			}
			if v := classify(item.value); v.kind == kindString && !blankString(v.text) {
				return v.text, true
			}
		}
	}
	return "", false
}

// hostFromValue extracts the host by the spec's steps; no URL library, so no parser differential.
func hostFromValue(value string) (host string, unparseable bool) {
	text := strings.Trim(value, " ")
	for _, r := range text {
		if r == '\\' || r < 0x20 || r == 0x7f || isPythonSpace(r) {
			return "", true
		}
	}
	original := text
	if !strings.Contains(text, "://") {
		text = "https://" + text
	}
	afterScheme := text[strings.Index(text, "://")+3:]
	authority := afterScheme
	if cut := strings.IndexAny(afterScheme, "/?#"); cut >= 0 {
		authority = afterScheme[:cut]
	}
	if strings.Count(authority, "[") != strings.Count(authority, "]") || (strings.Contains(authority, "[") && !strings.Contains(authority, "]")) {
		return "", true
	}
	hostinfo := authority[strings.LastIndex(authority, "@")+1:]
	if strings.HasPrefix(hostinfo, "[") {
		host, _, _ = strings.Cut(hostinfo[1:], "]")
	} else {
		host, _, _ = strings.Cut(hostinfo, ":")
	}
	host = pyLower(host)
	if host == "" && (strings.Contains(original, "://") || strings.HasPrefix(original, "//") || strings.Contains(original, "@")) {
		return "", true
	}
	return host, false
}

func (s *LocalScanner) egress(args any, metadata map[string]any) []map[string]any {
	host, unparseable := "", false
	for _, source := range s.spec.Detectors.EgressHost.Sources {
		var value string
		var found bool
		if source.From == "metadata" {
			if metadata == nil {
				continue
			}
			if source.Key != "" {
				var current any = metadata
				for _, part := range strings.Split(source.Key, ".") {
					next, ok := objectGet(current, part)
					if !ok {
						current = nil
						break
					}
					current = next
				}
				if n := classify(current); n.kind == kindString && !blankString(n.text) {
					value, found = n.text, true
				}
			} else {
				value, found = firstString(metadata, source.FirstNonEmptyOf)
			}
		} else {
			value, found = firstString(args, source.FirstNonEmptyOf)
		}
		if found {
			host, unparseable = hostFromValue(value)
			if host != "" || unparseable {
				break
			}
		}
	}
	if unparseable {
		return []map[string]any{{"kind": "egress_host", "verdict": "unresolved"}}
	}
	if host == "" {
		return nil
	}
	if len(host) <= s.hostMax && s.hostRegex.MatchString(host) {
		return []map[string]any{{"kind": "egress_host", "verdict": "not_allowlisted", "host": host}}
	}
	return []map[string]any{{"kind": "egress_host", "verdict": "unresolved"}}
}

// Recipient ----------------------------------------------------------------

var (
	addressKeys = map[string]struct{}{"email": {}, "address": {}, "emailaddress": {}, "value": {}, "mail": {}}
	displayKeys = map[string]struct{}{"name": {}, "displayname": {}, "firstname": {}, "lastname": {}, "fullname": {}, "type": {}, "role": {}, "label": {}}
)

// strings returns every recipient in a field's value; anything unreadable is "<unparsed>".
func (s *LocalScanner) recipientStrings(value any) []string {
	switch x := value.(type) {
	case nil:
		return nil
	case string:
		var out []string
		for _, raw := range strings.FieldsFunc(x, func(r rune) bool { return r == ',' || r == ';' }) {
			entry := asciiTrim(raw)
			if entry == "" {
				continue
			}
			var bracketed []string
			for _, m := range s.bracketed.FindAllStringSubmatch(entry, -1) {
				bracketed = append(bracketed, asciiTrim(m[1]))
			}
			rest := words(s.bracketed.ReplaceAllString(entry, " "))
			var loose []string
			for _, word := range rest {
				if strings.Contains(word, "@") {
					loose = append(loose, word)
				}
			}
			if len(bracketed) > 0 || len(loose) > 0 {
				out = append(out, bracketed...)
				out = append(out, loose...)
			} else {
				out = append(out, rest...)
			}
		}
		return out
	case []any:
		var out []string
		for _, element := range x {
			out = append(out, s.recipientStrings(element)...)
		}
		return out
	case object:
		var addresses, others []string
		for _, item := range x {
			name := normalKey(item.key)
			if _, ok := addressKeys[name]; ok {
				addresses = append(addresses, s.recipientStrings(item.value)...)
				continue
			}
			text, isText := item.value.(string)
			if _, display := displayKeys[name]; !display || !isText || strings.Contains(text, "@") {
				others = append(others, s.recipientStrings(item.value)...)
			}
		}
		var found []string
		for _, item := range addresses {
			if item != unparsed {
				found = append(found, item)
			}
		}
		anyAddressWithAt := false
		anyWithoutAt := false
		for _, item := range addresses {
			if strings.Contains(item, "@") {
				anyAddressWithAt = true
			} else {
				anyWithoutAt = true
			}
		}
		for _, item := range others {
			if strings.Contains(item, "@") {
				found = append(found, item)
			} else {
				anyWithoutAt = true
			}
		}
		if !anyAddressWithAt || anyWithoutAt {
			found = append(found, unparsed)
		}
		return found
	}
	return []string{unparsed}
}

// addressesInText reads bare addresses from positional text: at each '@' that
// follows a non-whitespace character, the domain directly after it.
func (s *LocalScanner) addressesInText(value any) []string {
	switch x := value.(type) {
	case string:
		if !strings.Contains(x, "@") {
			return nil
		}
		var out []string
		i := 0
		for i < len(x) {
			at := strings.IndexByte(x[i:], '@')
			if at < 0 {
				break
			}
			at += i
			matched := false
			if at > 0 {
				previous, _ := utf8.DecodeLastRuneInString(x[:at])
				if !isPythonSpace(previous) {
					if domain := s.textDomain.FindString(x[at+1:]); domain != "" {
						tooLong := len(domain) > maxDomain
						for _, label := range strings.Split(domain, ".") {
							if len(label) > maxLabel {
								tooLong = true
							}
						}
						if tooLong {
							out = append(out, unparsed)
						} else {
							out = append(out, "recipient@"+domain)
						}
						i = at + 1 + len(domain)
						matched = true
					}
				}
			}
			if !matched {
				i = at + 1
			}
		}
		return out
	case []any:
		var out []string
		for _, item := range x {
			out = append(out, s.addressesInText(item)...)
		}
		return out
	}
	return nil
}

// ambiguousRecipientInput is detectors.recipient.ambiguous_input: non-ASCII
// text that the Unicode (Python) and ASCII engines read differently.
func (s *LocalScanner) ambiguousRecipientInput(toolName string, tree any, fields map[string]struct{}, sending bool) bool {
	if !plain(toolName) {
		return true // (a)
	}
	var keysPlain func(v any) bool
	keysPlain = func(v any) bool {
		switch x := v.(type) {
		case object:
			for _, item := range x {
				if !plain(item.key) || !keysPlain(item.value) {
					return false
				}
			}
		case []any:
			for _, item := range x {
				if !keysPlain(item) {
					return false
				}
			}
		case string:
			return !hasOnlyPythonSpace(x) // (d)
		}
		return true
	}
	var textPlain func(v any) bool
	textPlain = func(v any) bool {
		switch x := v.(type) {
		case string:
			return !strings.Contains(x, "@") || plain(x)
		case []any:
			for _, item := range x {
				if !textPlain(item) {
					return false
				}
			}
		}
		return true
	}
	var ambiguous func(v any) bool
	ambiguous = func(v any) bool {
		switch x := v.(type) {
		case object:
			for _, item := range x {
				if !plain(item.key) {
					return true // (b)
				}
				name := normalKey(item.key)
				if _, ok := fields[name]; ok {
					if !keysPlain(item.value) {
						return true
					}
					continue
				}
				if sending && s.positional.MatchString(name) && !textPlain(item.value) {
					return true // (c)
				}
				if ambiguous(item.value) {
					return true
				}
			}
		case []any:
			for _, item := range x {
				if ambiguous(item) {
					return true
				}
			}
		}
		return false
	}
	return ambiguous(tree)
}

func (s *LocalScanner) collectRecipients(tree any, fields map[string]struct{}, sending bool) (found []string, dataField bool) {
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case object:
			for _, item := range x {
				name := normalKey(item.key)
				if _, ok := fields[name]; ok {
					found = append(found, s.recipientStrings(item.value)...)
					if _, move := s.moveFields[name]; move {
						dataField = true
					}
					continue
				}
				if sending && s.positional.MatchString(name) {
					found = append(found, s.addressesInText(item.value)...)
				}
				walk(item.value)
			}
		case []any:
			for _, item := range x {
				walk(item)
			}
		}
	}
	walk(tree)
	return found, dataField
}

// recipientFindings returns the findings, or ok=false when the check must be
// left out (ambiguous input).
func (s *LocalScanner) recipientFindings(toolName string, tree any) (findings []map[string]any, ok bool) {
	sending := s.sending.MatchString(toolName)
	fields := s.fields
	if sending {
		fields = make(map[string]struct{}, len(s.fields)+len(s.extraFields))
		for name := range s.fields {
			fields[name] = struct{}{}
		}
		for name := range s.extraFields {
			fields[name] = struct{}{}
		}
	}
	if s.ambiguousRecipientInput(toolName, tree, fields, sending) {
		return nil, false
	}
	values, dataField := s.collectRecipients(tree, fields, sending)
	dataMove := s.moveTool.MatchString(toolName) || dataField
	rule := &s.spec.Detectors.Recipient
	var domains []string
	unresolved := 0
	for _, value := range values {
		domain := ""
		if value != unparsed {
			if m := s.address.FindStringSubmatch(asciiTrim(value)); m != nil {
				domain = pyLower(m[1])
			}
		}
		if domain != "" && len(domain) <= s.hostMax && strings.Contains(domain, ".") && s.hostRegex.MatchString(domain) {
			seen := false
			for _, existing := range domains {
				if existing == domain {
					seen = true
					break
				}
			}
			if !seen {
				domains = append(domains, domain)
			}
		} else {
			unresolved++
		}
	}
	if len(domains) > 0 {
		shown := domains
		if len(shown) > rule.MaxDomains {
			shown = shown[:rule.MaxDomains]
		}
		findings = append(findings, map[string]any{"kind": "recipient", "status": "outside", "data_move": dataMove, "domains": shown})
	}
	extra := unresolved
	if len(domains) > rule.MaxDomains {
		extra++
	}
	for i := 0; i < min(extra, rule.MaxUnresolvedFindings); i++ {
		findings = append(findings, map[string]any{"kind": "recipient", "status": "unresolved", "data_move": dataMove})
	}
	return findings, true
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

// Finding is one entry of a report: kind plus the fields of that kind.
type Finding = map[string]any

// ScanResult is the scanned checks and their findings, before the report is sized.
type ScanResult struct {
	Scanned  []string
	Findings []Finding
}

// ScannerInfo identifies the scanner in a report.
type ScannerInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	RulesetID   string `json:"ruleset_id"`
	RulesetHash string `json:"ruleset_hash"`
}

// ClientFindings is the client_findings request field.
type ClientFindings struct {
	Version  int         `json:"version"`
	Scanner  ScannerInfo `json:"scanner"`
	Scanned  []string    `json:"scanned"`
	Findings []Finding   `json:"findings"`
}

// Scan reports {scanned, findings} for the raw arguments. A check that panics
// or cannot be answered is not in Scanned and has no findings. It never panics.
func (s *LocalScanner) Scan(toolName string, args any, metadata map[string]any) (result ScanResult) {
	result = ScanResult{Scanned: []string{}, Findings: []Finding{}}
	if classify(args).kind != kindObject {
		return result
	}
	results := map[string][]Finding{}
	run := func(check string, fn func() ([]Finding, bool)) {
		defer func() {
			if recover() != nil {
				// The check's name only: a panic message could quote a value.
				log.Printf("thoth: local scan check %s failed; reporting it as not scanned", check)
			}
		}()
		if s.panicHook != nil {
			s.panicHook(check)
		}
		if found, ok := fn(); ok {
			results[check] = found
		}
	}
	var tree any
	var truncated, walked bool
	boundedTree := func() (any, bool) {
		if !walked {
			tree, truncated = s.bounded(args)
			walked = true
		}
		return tree, truncated
	}
	run("dlp", func() ([]Finding, bool) {
		t, cut := boundedTree()
		if cut {
			return nil, false
		}
		var leaves []string
		leavesOf(t, &leaves)
		return s.dlp(leaves), true
	})
	run("sensitive_path", func() ([]Finding, bool) { return s.sensitivePath(args), true })
	run("egress_host", func() ([]Finding, bool) { return s.egress(args, metadata), true })
	run("recipient", func() ([]Finding, bool) {
		t, cut := boundedTree()
		if cut {
			return nil, false
		}
		return s.recipientFindings(toolName, t)
	})
	for _, check := range s.scannedOrder {
		if found, ok := results[check]; ok {
			result.Scanned = append(result.Scanned, check)
			result.Findings = append(result.Findings, found...)
		}
	}
	return result
}

func (s *LocalScanner) size(report *ClientFindings) int {
	raw, err := json.Marshal(report)
	if err != nil {
		return s.MaxBytes + 1
	}
	return len(raw)
}

// ClientFindings builds the client_findings request field, or nil when
// nothing was scanned. If the report would exceed the server's size or count
// bound, checks are left out (recipient first, then egress_host) rather than
// sending a report the server would reject.
func (s *LocalScanner) ClientFindings(toolName string, args any, metadata map[string]any) (report *ClientFindings) {
	defer func() {
		if recover() != nil {
			log.Printf("thoth: local scan failed; sending no findings")
			report = nil
		}
	}()
	result := s.Scan(toolName, args, metadata)
	scanner := ScannerInfo{Name: ScannerName, Version: s.Version, RulesetID: s.RulesetID, RulesetHash: s.RulesetHash}
	scanned := append([]string{}, result.Scanned...)
	findings := append([]Finding{}, result.Findings...)
	for _, drop := range []string{"", "recipient", "egress_host"} {
		if drop != "" {
			kept := scanned[:0:0]
			for _, check := range scanned {
				if check != drop {
					kept = append(kept, check)
				}
			}
			scanned = kept
			keptFindings := findings[:0:0]
			for _, finding := range findings {
				if finding["kind"] != drop {
					keptFindings = append(keptFindings, finding)
				}
			}
			findings = keptFindings
		}
		candidate := &ClientFindings{Version: ReportVersion, Scanner: scanner, Scanned: scanned, Findings: findings}
		if len(findings) <= s.maxFindings && s.size(candidate) <= s.MaxBytes {
			if len(scanned) == 0 {
				return nil
			}
			return candidate
		}
	}
	return nil
}

var (
	loadOnce    sync.Once
	loadedScan  *LocalScanner
	loadedError error
)

// LoadScanner is the scanner built from the embedded spec, or nil (logged
// once) when it cannot be built. A tampered or mismatching spec is refused.
func LoadScanner() *LocalScanner {
	loadOnce.Do(func() {
		loadedScan, loadedError = NewLocalScanner(embeddedSpec, "")
		if loadedError != nil {
			log.Printf("thoth: local scan is unavailable (detector spec could not be loaded); sending no findings")
			loadedScan = nil
		}
	})
	return loadedScan
}
