package thoth

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

const pinnedRulesetHash = "db797fde60f300719b9dac8a360efd6ce8b1f7313587cc714aebf7a93428434b"

type goldenCase struct {
	ID        string         `json:"id"`
	Group     string         `json:"group"`
	ToolName  string         `json:"tool_name"`
	Arguments any            `json:"arguments"`
	Metadata  map[string]any `json:"metadata"`
	Expected  struct {
		Scanned  []string         `json:"scanned"`
		Findings []map[string]any `json:"findings"`
	} `json:"expected"`
}

func loadGolden(t *testing.T) (hash string, cases []goldenCase) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "sdk", "detectors_golden.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		RulesetHash string       `json:"ruleset_hash"`
		Cases       []goldenCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.RulesetHash, doc.Cases
}

func newTestScanner(t *testing.T) *LocalScanner {
	t.Helper()
	s, err := NewLocalScanner(embeddedSpec, "9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// asJSON makes a result comparable with the golden's decoded JSON.
func asJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestIdentityAndPackaging(t *testing.T) {
	s := newTestScanner(t)
	if s.RulesetHash != pinnedRulesetHash {
		t.Fatalf("ruleset hash %s, want the pinned %s", s.RulesetHash, pinnedRulesetHash)
	}
	hash, _ := loadGolden(t)
	if hash != pinnedRulesetHash {
		t.Fatalf("golden hash %s", hash)
	}
	report := s.ClientFindings("tool", map[string]any{"text": "hello"}, nil)
	if report == nil || report.Scanner != (ScannerInfo{Name: "atensec-thoth-go", Version: "9.9.9", RulesetID: "thoth-detectors.v1", RulesetHash: pinnedRulesetHash}) {
		t.Fatalf("scanner identity %+v", report)
	}
	// The server's name and version constraints.
	if !strings.HasPrefix(ScannerName, "atensec-thoth") || len(ScannerName) > 64 {
		t.Fatal(ScannerName)
	}
	for _, in := range []string{"v0.1.22", "(devel)", "", "v0.1.22-0.20261108123456-abcdef123456+dirty"} {
		out := cleanVersion(in)
		if len(out) == 0 || len(out) > 32 || !(out[0] >= '0' && out[0] <= '9' || out[0] >= 'A' && out[0] <= 'Z' || out[0] >= 'a' && out[0] <= 'z') {
			t.Errorf("cleanVersion(%q) = %q", in, out)
		}
	}
	if cleanVersion("v0.1.22") != "0.1.22" || cleanVersion("(devel)") != "0" {
		t.Error("cleanVersion should drop the v and map a development build to 0")
	}
}

func TestRefusesASpecThatDoesNotMatchItsHash(t *testing.T) {
	tampered := bytes.Replace(embeddedSpec, []byte(`bAKIA[`), []byte(`bAKIB[`), 1)
	if bytes.Equal(tampered, embeddedSpec) {
		t.Fatal("test setup: spec text not found")
	}
	if _, err := NewLocalScanner(tampered, ""); err == nil {
		t.Fatal("a spec that does not match its ruleset_hash must be refused")
	}
	if _, err := NewLocalScanner([]byte("{"), ""); err == nil {
		t.Fatal("invalid JSON must be refused")
	}
}

func TestEmbeddedSpecIsByteIdenticalToTheSharedCopies(t *testing.T) {
	features := filepath.Join("..", "..", "..", "..", "python", "libs", "features")
	if _, err := os.Stat(features); err != nil {
		t.Skip("the SDK is tested outside the monorepo")
	}
	want, err := os.ReadFile(filepath.Join(features, "thoth_features", "detectors.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(embeddedSpec, want) {
		t.Fatal("_internal_thoth/detectors.v1.json differs from backend/python/libs/features/thoth_features/detectors.v1.json")
	}
	for _, name := range []string{"detectors_golden.v1.json"} {
		got, _ := os.ReadFile(filepath.Join("..", "testdata", "sdk", name))
		shared, err := os.ReadFile(filepath.Join(features, "fixtures", name))
		if err != nil || !bytes.Equal(got, shared) {
			t.Fatalf("testdata/sdk/%s differs from the shared copy", name)
		}
	}
	ts, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "frontend", "packages", "thoth", "testdata", "sdk", "data_handling_golden.json"))
	if err == nil {
		got, _ := os.ReadFile(filepath.Join("..", "testdata", "sdk", "data_handling_golden.json"))
		if !bytes.Equal(got, ts) {
			t.Fatal("testdata/sdk/data_handling_golden.json differs from the TypeScript SDK's copy")
		}
	}
}

func TestLoadScannerUsesTheEmbeddedSpec(t *testing.T) {
	s := LoadScanner()
	if s == nil || s.RulesetHash != pinnedRulesetHash {
		t.Fatalf("%+v", s)
	}
}

func TestGoldenCases(t *testing.T) {
	_, cases := loadGolden(t)
	s := newTestScanner(t)
	groups := map[string]bool{}
	for _, c := range cases {
		groups[c.Group] = true
	}
	for _, g := range []string{"dlp", "bounds", "sensitive_path", "egress_host", "recipient", "negative", "known_divergence", "ambiguous"} {
		if !groups[g] {
			t.Errorf("golden has no %q group", g)
		}
	}
	if len(cases) != 174 {
		t.Errorf("%d golden cases, want 174", len(cases))
	}
	for _, c := range cases {
		if c.Group == "known_divergence" {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			got := s.Scan(c.ToolName, c.Arguments, c.Metadata)
			if domains, ok := goKeyOrderAnswers[c.ID]; ok {
				// A Go map has no insertion order, so keys are read in sorted order
				// and domains from different fields come out in that order. Same
				// domains, same everything else.
				sameDomains := asJSON(t, got.Findings[1]["domains"]) == domains
				want := asJSON(t, c.Expected.Findings[1]["domains"])
				if !sameDomains || len(c.Expected.Findings[1]["domains"].([]any)) != 3 || want == domains {
					t.Fatalf("pinned Go order %s; got %s; golden %s", domains, asJSON(t, got.Findings[1]["domains"]), want)
				}
				return
			}
			want := map[string]any{"scanned": c.Expected.Scanned, "findings": nonNil(c.Expected.Findings)}
			have := map[string]any{"scanned": got.Scanned, "findings": got.Findings}
			if asJSON(t, have) != asJSON(t, want) {
				t.Fatalf("\n got %s\nwant %s", asJSON(t, have), asJSON(t, want))
			}
		})
	}
}

// goKeyOrderAnswers pins the cases whose golden answer depends on the order
// keys appear in the JSON object, which a Go map does not keep. The scanner
// visits keys in sorted order instead (bcc, cc, to).
var goKeyOrderAnswers = map[string]string{
	"recipient.to_list_cc_bcc": `["x.com","z.net","y.org"]`,
}

func nonNil(f []map[string]any) []map[string]any {
	if f == nil {
		return []map[string]any{}
	}
	return f
}

// The server (Python) reads \b \w \d \s as Unicode; Go is ASCII there, as the
// spec requires. Go differs from the TypeScript answers in one place: its
// case-insensitive matching folds K (U+212A) to k as Python's does, so a
// recipient domain written with the Kelvin sign resolves to k.com, the
// server's own answer. These are the answers this scanner gives, pinned so a
// change in the engine shows up. The recorded server answers are not
// conformance targets.
func TestKnownDivergenceCasesPinTheGoAnswers(t *testing.T) {
	_, cases := loadGolden(t)
	s := newTestScanner(t)
	ssn := []map[string]any{{"kind": "dlp", "category": "ssn", "count": 1}}
	email := []map[string]any{{"kind": "dlp", "category": "email", "count": 1}}
	answers := map[string][]map[string]any{
		"known_divergence.non_ascii_letter_before_ssn":  ssn,
		"known_divergence.cjk_before_email":             email,
		"known_divergence.arabic_indic_digits_ssn":      {},
		"known_divergence.nbsp_in_phone":                {},
		"known_divergence.recipient_kelvin_sign_domain": {{"kind": "recipient", "status": "outside", "data_move": false, "domains": []string{"k.com"}}},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		if c.Group != "known_divergence" {
			continue
		}
		seen[c.ID] = true
		want, ok := answers[c.ID]
		if !ok {
			t.Errorf("no Go answer pinned for %s", c.ID)
			continue
		}
		got := s.Scan(c.ToolName, c.Arguments, c.Metadata)
		if asJSON(t, got.Scanned) != asJSON(t, c.Expected.Scanned) {
			t.Errorf("%s scanned %v", c.ID, got.Scanned)
		}
		if asJSON(t, got.Findings) != asJSON(t, want) {
			t.Errorf("%s\n got %s\nwant %s", c.ID, asJSON(t, got.Findings), asJSON(t, want))
		}
	}
	for id := range answers {
		if !seen[id] {
			t.Errorf("%s is pinned but not in the golden", id)
		}
	}
}

func TestSpacesMatchPythonIsspaceAndTheSpecsTwentyThree(t *testing.T) {
	// Python's str.isspace() is Go's unicode.IsSpace plus U+001C to U+001F.
	for r := rune(0); r <= unicode.MaxRune; r++ {
		want := unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
		if isPythonSpace(r) != want {
			t.Fatalf("U+%04X: isPythonSpace=%v, want %v", r, isPythonSpace(r), want)
		}
	}
	count := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if isOnlyPythonSpace(r) {
			count++
		}
	}
	if count != 23 {
		t.Fatalf("%d characters, the spec lists 23", count)
	}
	for _, r := range []rune{0x1c, 0x1d, 0x1e, 0x1f, 0x85, 0xa0, 0x1680, 0x2000, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000} {
		if !isOnlyPythonSpace(r) {
			t.Errorf("U+%04X", r)
		}
	}
	for _, r := range []rune{' ', '\t', '\n', 0x0b, '\f', '\r', 0x200b, 0xad} {
		if isOnlyPythonSpace(r) {
			t.Errorf("U+%04X is ASCII whitespace or not whitespace", r)
		}
	}
}

func TestEveryUnicodeSpaceInARecipientFieldLeavesRecipientOut(t *testing.T) {
	s := newTestScanner(t)
	for r := rune(0); r <= 0x3000; r++ {
		if !isOnlyPythonSpace(r) {
			continue
		}
		for _, args := range []map[string]any{
			{"to": "a@x.com" + string(r) + "b@y.org"},
			{"to": []any{"<a" + string(r) + "b@x.com>"}},
			{"to": map[string]any{"email": "a" + string(r) + "b@x.com"}},
		} {
			got := s.Scan("send_email", args, nil)
			for _, check := range got.Scanned {
				if check == "recipient" {
					t.Fatalf("U+%04X in %v: recipient was scanned", r, args)
				}
			}
		}
	}
	// Zero-width and accented text in a field value still scans.
	got := s.Scan("send_email", map[string]any{"to": "José <jose@x.com>"}, nil)
	if len(got.Scanned) != 4 {
		t.Fatalf("%v", got.Scanned)
	}
}

func TestRE2SemanticsMatchTheSpecNotTheEngineDefaults(t *testing.T) {
	s := newTestScanner(t)
	count := func(text string) []map[string]any {
		return s.Scan("tool", map[string]any{"t": text}, nil).Findings
	}
	// RE2's \s has no vertical tab; the spec's does.
	if got := count("555\v123\v4567"); len(got) != 1 || got[0]["category"] != "phone" {
		t.Errorf("a vertical tab separates phone digits: %v", got)
	}
	if got := count("password:\v hunter2"); len(got) != 1 || got[0]["category"] != "credential" {
		t.Errorf("a vertical tab after the colon: %v", got)
	}
	// \b is ASCII: an accented letter is not a word character.
	if got := count("é123-45-6789"); len(got) != 1 {
		t.Errorf("%v", got)
	}
	// \d is ASCII.
	if got := count("١٢٣-٤٥-٦٧٨٩"); len(got) != 0 {
		t.Errorf("%v", got)
	}
	// Case-insensitive matching with the Kelvin sign and long s: Go folds them as Python does.
	if got := count("ſecret=1"); len(got) != 1 {
		t.Logf("long s: %v", got)
	}
	// DLP counts per step on the text earlier steps left.
	got := count("password=AKIAABCDEFGHIJKLMNOP")
	if len(got) != 1 || got[0]["count"] != 2 {
		t.Errorf("password=AKIA... counts a credential twice: %v", got)
	}
	// The replacement is literal: $1 and \1 in a value are not expanded.
	if got := count(`password=$1\1 ${x}`); len(got) != 1 || got[0]["count"] != 1 {
		t.Errorf("%v", got)
	}
}

func TestWhatLeavesTheProcess(t *testing.T) {
	s := newTestScanner(t)
	args := map[string]any{
		"to":   "Very.Secret.Name+tag@Corp.Example.com",
		"url":  "https://user:hunter2@Api.Example.org/path?token=abc",
		"path": "/data/patient_records.csv",
		"text": "ssn 123-45-6789 password=hunter2",
	}
	text := strings.ToLower(asJSON(t, s.ClientFindings("send_email", args, nil)))
	for _, leaked := range []string{"very.secret", "secret.name", "hunter2", "123-45-6789", "patient_records", "/data", "token=abc", "user:"} {
		if strings.Contains(text, leaked) {
			t.Errorf("report leaks %q: %s", leaked, text)
		}
	}
	for _, kept := range []string{"corp.example.com", "api.example.org"} {
		if !strings.Contains(text, kept) {
			t.Errorf("report lacks %q: %s", kept, text)
		}
	}
}

func TestReportBoundsDropRecipientThenEgress(t *testing.T) {
	s := newTestScanner(t)
	var domains []any
	for i := 0; i < 10; i++ {
		domains = append(domains, "a@"+strings.Repeat("x", 63)+"."+strings.Repeat("y", 63)+"."+strings.Repeat("z", 63)+"."+strings.Repeat("w", 58)+string(rune('0'+i))+".com")
	}
	for i := 0; i < 12; i++ {
		domains = append(domains, "Bob")
	}
	args := map[string]any{"to": domains, "url": "https://evil.example.com/"}
	full := s.ClientFindings("send_email", args, nil)
	if full == nil || !contains(full.Scanned, "recipient") {
		t.Fatalf("%+v", full)
	}
	// The real bound is 4096 bytes; a smaller one proves the report is trimmed, not sent half.
	s.MaxBytes = len(asJSON(t, full)) - 1
	trimmed := s.ClientFindings("send_email", args, nil)
	if trimmed == nil || len(asJSON(t, trimmed)) > s.MaxBytes {
		t.Fatalf("%+v", trimmed)
	}
	if contains(trimmed.Scanned, "recipient") || !contains(trimmed.Scanned, "egress_host") {
		t.Errorf("recipient should be dropped first: %v", trimmed.Scanned)
	}
	for _, f := range trimmed.Findings {
		if f["kind"] == "recipient" {
			t.Error("recipient finding kept")
		}
	}
	s.MaxBytes = len(asJSON(t, trimmed)) - 1
	again := s.ClientFindings("send_email", args, nil)
	if again == nil || contains(again.Scanned, "egress_host") || contains(again.Scanned, "recipient") {
		t.Errorf("egress_host should be dropped second: %+v", again)
	}
	s.MaxBytes = 10
	if s.ClientFindings("send_email", args, nil) != nil {
		t.Error("a report that cannot fit is not sent")
	}
}

func TestCountBoundDropsChecksToo(t *testing.T) {
	s := newTestScanner(t)
	s.maxFindings = 2
	args := map[string]any{"to": []any{"Bob", "Carol", "Dave"}}
	report := s.ClientFindings("send_email", args, nil)
	if report == nil || len(report.Findings) > 2 || contains(report.Scanned, "recipient") {
		t.Errorf("%+v", report)
	}
}

func contains(list []string, item string) bool {
	for _, x := range list {
		if x == item {
			return true
		}
	}
	return false
}

func TestNonObjectArgumentsSendNothing(t *testing.T) {
	s := newTestScanner(t)
	for _, args := range []any{[]any{"a", "b"}, nil, "text", 3, []string{"x"}} {
		if s.ClientFindings("tool", args, nil) != nil {
			t.Errorf("%v", args)
		}
	}
	if s.ClientFindings("tool", map[string]any{}, nil) == nil {
		t.Error("empty arguments are an object; all four checks completed clean")
	}
}

func TestACheckThatPanicsIsLeftOutNotReportedClean(t *testing.T) {
	s := newTestScanner(t)
	var logs bytes.Buffer
	restore := captureLog(&logs)
	defer restore()
	s.panicHook = func(check string) {
		if check == "sensitive_path" {
			panic("cannot read CANARY-9f3a")
		}
	}
	got := s.Scan("tool", map[string]any{"path": "/x/patient.txt", "text": "123-45-6789"}, nil)
	if contains(got.Scanned, "sensitive_path") {
		t.Error("a panicking check must not be in scanned")
	}
	for _, f := range got.Findings {
		if f["kind"] == "sensitive_path" {
			t.Error("a panicking check has no findings")
		}
	}
	if strings.Join(got.Scanned, ",") != "dlp,egress_host,recipient" {
		t.Errorf("%v", got.Scanned)
	}
	if strings.Contains(logs.String(), "CANARY") || !strings.Contains(logs.String(), "sensitive_path") {
		t.Errorf("the log names the check and never the panic message: %q", logs.String())
	}
	// Every check panicking sends nothing.
	s.panicHook = func(string) { panic("x") }
	if s.ClientFindings("tool", map[string]any{"text": "x"}, nil) != nil {
		t.Error("no report when every check fails")
	}
}

func TestBoundsLeaveDLPAndRecipientOut(t *testing.T) {
	s := newTestScanner(t)
	wide := make([]any, 6000)
	for i := range wide {
		wide[i] = "x"
	}
	got := s.Scan("send_email", map[string]any{"items": wide, "to": "a@x.com"}, nil)
	if strings.Join(got.Scanned, ",") != "sensitive_path,egress_host" {
		t.Errorf("%v", got.Scanned)
	}
	var deep any = "123-45-6789"
	for i := 0; i < 20; i++ {
		deep = map[string]any{"n": deep}
	}
	got = s.Scan("tool", map[string]any{"deep": deep}, nil)
	if contains(got.Scanned, "dlp") || contains(got.Scanned, "recipient") {
		t.Errorf("%v", got.Scanned)
	}
	// A cycle is truncated by the depth bound; it neither hangs nor overflows the stack.
	loop := map[string]any{"a": "123-45-6789"}
	loop["self"] = loop
	got = s.Scan("tool", loop, nil)
	if contains(got.Scanned, "dlp") {
		t.Errorf("%v", got.Scanned)
	}
	// Exactly the bound is fine: depth 16 is visited, 17 is not.
	var edge any = "123-45-6789"
	for i := 0; i < 15; i++ {
		edge = map[string]any{"n": edge}
	}
	got = s.Scan("tool", map[string]any{"edge": edge}, nil)
	if !contains(got.Scanned, "dlp") {
		t.Errorf("depth 16 is within the bound: %v", got.Scanned)
	}
}

func TestUnparseableHostIsUnresolvedNotNoHost(t *testing.T) {
	s := newTestScanner(t)
	for _, url := range []string{"https:///x", "http://@", "//x.example", `http://a\b.example`, "http://[::1", "http://a b.example", "http://a b.example", "http://a\tb.example"} {
		got := s.Scan("fetch", map[string]any{"url": url}, nil).Findings
		if asJSON(t, got) != `[{"kind":"egress_host","verdict":"unresolved"}]` {
			t.Errorf("%q: %s", url, asJSON(t, got))
		}
	}
	if got := s.Scan("fetch", map[string]any{"url": ":8080"}, nil).Findings; len(got) != 0 {
		t.Errorf("%v", got)
	}
	// U+0130 lower-cases to two characters in Python and JavaScript, so the host stays invalid.
	got := s.Scan("fetch", map[string]any{"url": "https://İ.example.com/"}, nil).Findings
	if asJSON(t, got) != `[{"kind":"egress_host","verdict":"unresolved"}]` {
		t.Errorf("%s", asJSON(t, got))
	}
}

func TestEgressFromRequestMetadata(t *testing.T) {
	s := newTestScanner(t)
	meta := map[string]any{"secrets_broker": map[string]any{"target_host": "Vault.Example.com"}}
	got := s.Scan("tool", map[string]any{"url": "https://other.example.org"}, meta).Findings
	if asJSON(t, got) != `[{"host":"vault.example.com","kind":"egress_host","verdict":"not_allowlisted"}]` {
		t.Errorf("%s", asJSON(t, got))
	}
	got = s.Scan("tool", map[string]any{}, map[string]any{"target_host": "https://svc.example.net:8443/x"}).Findings
	if asJSON(t, got) != `[{"host":"svc.example.net","kind":"egress_host","verdict":"not_allowlisted"}]` {
		t.Errorf("%s", asJSON(t, got))
	}
}

func TestTypedGoValuesAreScannedLikeJSON(t *testing.T) {
	type mail struct {
		To      []string `json:"to"`
		Subject string   `json:"subject"`
	}
	s := newTestScanner(t)
	got := s.Scan("send_email", map[string]any{
		"arg0":    mail{To: []string{"a@x.com"}, Subject: "ssn 123-45-6789"},
		"cc":      []string{"b@y.org"},
		"headers": map[string]string{"x": "AKIAABCDEFGHIJKLMNOP"},
		"n":       3,
		"ptr":     &mail{},
	}, nil)
	want := `[{"category":"credential","count":1,"kind":"dlp"},{"category":"email","count":2,"kind":"dlp"},{"category":"ssn","count":1,"kind":"dlp"},{"data_move":false,"domains":["x.com","y.org"],"kind":"recipient","status":"outside"}]`
	if asJSON(t, got.Findings) != want {
		t.Errorf("\n got %s\nwant %s", asJSON(t, got.Findings), want)
	}
	if len(got.Scanned) != 4 {
		t.Errorf("%v", got.Scanned)
	}
}

func TestPositionalTextForPositionalArguments(t *testing.T) {
	// The Go SDK sends a non-map call as arg0, arg1: the positional-key rule reads them for sending tools.
	s := newTestScanner(t)
	got := s.Scan("send_email", map[string]any{"arg0": "please send to jane@corp.example.com today"}, nil).Findings
	if !strings.Contains(asJSON(t, got), `"domains":["corp.example.com"]`) {
		t.Errorf("%s", asJSON(t, got))
	}
	got = s.Scan("lookup", map[string]any{"arg0": "jane@corp.example.com"}, nil).Findings
	if strings.Contains(asJSON(t, got), "recipient") {
		t.Errorf("a non-sending tool reads no bare addresses: %s", asJSON(t, got))
	}
}

func TestSourceDoesNotUseNetURLOrUnicodeAwareExtras(t *testing.T) {
	src, err := os.ReadFile("localscan.go")
	if err != nil {
		t.Fatal(err)
	}
	code := string(src)
	if strings.Contains(code, `"net/url"`) || strings.Contains(code, "url.Parse") {
		t.Error("hosts must be extracted by the spec's steps, not net/url")
	}
	data, err := os.ReadFile("datahandling.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"net/url"`) {
		t.Error("net/url in datahandling.go")
	}
}

type cyclic struct {
	Name string
	Next *cyclic
}

func TestOddGoValuesNeverPanicOrHang(t *testing.T) {
	s := newTestScanner(t)
	loop := &cyclic{Name: "a"}
	loop.Next = loop
	list := []any{nil}
	list[0] = list
	args := map[string]any{
		"chan":   make(chan int),
		"fn":     func() {},
		"cyc":    loop,
		"list":   list,
		"nilmap": map[string]any(nil),
		"nilptr": (*cyclic)(nil),
		"cplx":   complex(1, 2),
		"text":   "123-45-6789",
		"bytes":  []byte("x"),
	}
	got := s.Scan("send_email", args, nil)
	if !contains(got.Scanned, "sensitive_path") || !contains(got.Scanned, "egress_host") {
		t.Errorf("%v", got.Scanned)
	}
	// The cycle is cut by the depth bound, so dlp and recipient are left out rather than reported clean.
	if contains(got.Scanned, "dlp") || contains(got.Scanned, "recipient") {
		t.Errorf("%v", got.Scanned)
	}
	for _, mode := range []string{ModeHash, ModeRedact} {
		_, out := TransformArguments(args, mode, "s")
		if text := canonicalJSON(out); strings.Contains(text, "123-45-6789") {
			t.Errorf("%s leaked", mode)
		}
	}
}

func TestEnforcerScansEmptyArgumentsAsAnObject(t *testing.T) {
	s := newTestScanner(t)
	report := s.ClientFindings("tool", map[string]any{}, map[string]any{"url": "https://x.example.com"})
	if report == nil || !contains(report.Scanned, "egress_host") || len(report.Findings) != 1 {
		t.Fatalf("%+v", report)
	}
}
