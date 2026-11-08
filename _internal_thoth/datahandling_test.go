package thoth

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCanary = "CANARY-9f3a-secret-value"

type dhGolden struct {
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	Mode            string `json:"mode"`
	Salt            string `json:"salt"`
	Input           any    `json:"input"`
	Expected        any    `json:"expected"`
	ExpectedOmitted bool   `json:"expected_omitted"`
}

func loadDataHandlingGolden(t *testing.T, useNumber bool) []dhGolden {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "sdk", "data_handling_golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []dhGolden `json:"cases"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if useNumber {
		decoder.UseNumber()
	}
	if err := decoder.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	return doc.Cases
}

// Every case must reproduce `expected` byte for byte, compared as canonical JSON.
func TestDataHandlingGoldenFixture(t *testing.T) {
	for _, useNumber := range []bool{false, true} {
		cases := loadDataHandlingGolden(t, useNumber)
		if len(cases) != 40 {
			t.Fatalf("%d golden cases, want 40", len(cases))
		}
		for _, c := range cases {
			c := c
			t.Run(c.Name, func(t *testing.T) {
				switch c.Kind {
				case "tool_arguments":
					keep, out := TransformArguments(c.Input, c.Mode, c.Salt)
					if c.ExpectedOmitted {
						if keep {
							t.Fatal("expected the arguments to be omitted")
						}
						return
					}
					if !keep || canonicalJSON(out) != canonicalJSON(c.Expected) {
						t.Fatalf("\n got %s\nwant %s", canonicalJSON(out), canonicalJSON(c.Expected))
					}
				case "prompt":
					keep, out := TransformPrompt(c.Input, c.Mode, c.Salt)
					if c.ExpectedOmitted {
						if keep {
							t.Fatal("expected the prompt to be omitted")
						}
						return
					}
					if !keep || canonicalJSON(out) != canonicalJSON(c.Expected) {
						t.Fatalf("\n got %s\nwant %s", canonicalJSON(out), canonicalJSON(c.Expected))
					}
				case "context":
					input, _ := c.Input.(map[string]any)
					got := TransformContext(input, c.Mode, c.Salt)
					if canonicalJSON(got) != canonicalJSON(c.Expected) {
						t.Fatalf("\n got %s\nwant %s", canonicalJSON(got), canonicalJSON(c.Expected))
					}
				default:
					t.Fatalf("unknown kind %q", c.Kind)
				}
			})
		}
	}
}

func TestCanonicalJSON(t *testing.T) {
	for name, tc := range map[string]struct {
		in   any
		want string
	}{
		"sorted keys, no spaces":    {map[string]any{"b": 1, "a": []any{true, nil, "x"}}, `{"a":[true,null,"x"],"b":1}`},
		"not html escaped":          {"<a href=\"x\">&</a>", `"<a href=\"x\">&</a>"`},
		"non-ASCII kept":            {"café ☃ 日本語", `"café ☃ 日本語"`},
		"line separator kept":       {"a b c", "\"a b c\""},
		"control characters":        {"\x00\x1f\b\f\n\r\t\x7f", "\"\\u0000\\u001f\\b\\f\\n\\r\\t\x7f\""},
		"sorted by code point":      {map[string]any{"é": 1, "z": 2, "Z": 3, "\U0001f600": 4, "￿": 5}, "{\"Z\":3,\"z\":2,\"é\":1,\"￿\":5,\"\U0001f600\":4}"},
		"float without exponent":    {1.5, `1.5`},
		"whole float is an integer": {3.0, `3`},
		"large float":               {1e21, `1e+21`},
		"small float":               {1e-7, `1e-7`},
		"negative zero":             {math.Copysign(0, -1), `0`},
		"int64":                     {int64(math.MaxInt64), `9223372036854775807`},
		"uint64":                    {uint64(math.MaxUint64), `18446744073709551615`},
		"json.Number":               {json.Number("12345678901234567890"), `12345678901234567890`},
		"NaN is a string":           {math.NaN(), `"NaN"`},
		"Inf is a string":           {math.Inf(-1), `"-Infinity"`},
		"typed slice":               {[]string{"a", "b"}, `["a","b"]`},
		"typed map":                 {map[string]int{"b": 2, "a": 1}, `{"a":1,"b":2}`},
		"nil map is null":           {map[string]any(nil), `null`},
		"nil pointer":               {(*string)(nil), `null`},
		"struct by json tags": {struct {
			A int    `json:"a"`
			B string `json:"b,omitempty"`
		}{A: 1}, `{"a":1}`},
		"bytes are base64 text": {[]byte("hi"), `"aGk="`},
		"channel has no value":  {make(chan int), `"chan int"`},
	} {
		if got := canonicalJSON(tc.in); got != tc.want {
			t.Errorf("%s: got %s, want %s", name, got, tc.want)
		}
	}
}

func TestCanonicalJSONIsBoundedForCycles(t *testing.T) {
	loop := map[string]any{}
	loop["self"] = loop
	if got := canonicalJSON(loop); !strings.Contains(got, TruncatedMarker) {
		t.Fatalf("%.200s", got)
	}
}

func TestHashValueFormat(t *testing.T) {
	got := HashValue("golden-salt-v1", "alice@example.com")
	if got != "hmac-sha256:bf8a0dc3bf9ec6f1c64cbe369d94579e29bdbf1660639992118b01257ddb0c4d" {
		t.Fatal(got)
	}
	// Salt matters; the same salt is stable.
	if HashValue("other", "alice@example.com") == got || HashValue("golden-salt-v1", "alice@example.com") != got {
		t.Fatal("hash depends on the salt only")
	}
}

func TestTransformsDoNotModifyTheirInput(t *testing.T) {
	value := map[string]any{"path": "/tmp/r.txt", "n": map[string]any{"count": 3, "list": []any{"a", nil}}}
	before, _ := json.Marshal(value)
	HashArguments(value, "s")
	RedactArguments(value)
	TransformContext(map[string]any{"prompt": "x", "nested": map[string]any{"text": "y"}}, ModeHash, "s")
	after, _ := json.Marshal(value)
	if string(before) != string(after) {
		t.Fatal("input modified")
	}
}

func TestNeverLetsAnOriginalValuePastTheBounds(t *testing.T) {
	var deep any = testCanary + "-deep"
	for i := 0; i < 20; i++ {
		deep = map[string]any{"n": deep}
	}
	for _, out := range []any{RedactArguments(deep), HashArguments(deep, "s")} {
		text := canonicalJSON(out)
		if strings.Contains(text, "CANARY") || !strings.Contains(text, TruncatedMarker) {
			t.Fatalf("%s", text)
		}
	}
	wide := make([]any, 6000)
	for i := range wide {
		wide[i] = "secret-" + string(rune('a'+i%26))
	}
	list := HashArguments(wide, "s").([]any)
	if list[len(list)-1] != TruncatedMarker {
		t.Fatalf("last item %v", list[len(list)-1])
	}
	text, _ := json.Marshal(list)
	if strings.Contains(string(text), "secret-") {
		t.Fatal("an original value passed through")
	}
	keys := map[string]any{}
	for i := 0; i < 6000; i++ {
		keys["k"+string(rune('a'+i%26))+strings.Repeat("x", i/26)] = "secret"
	}
	object := RedactArguments(keys).(map[string]any)
	if object["_truncated"] != TruncatedMarker {
		t.Fatal("a wide object gains _truncated")
	}
	// A cycle ends at the depth bound; it does not overflow the stack.
	loop := map[string]any{"a": testCanary}
	loop["self"] = loop
	text, _ = json.Marshal(HashArguments(loop, "s"))
	if strings.Contains(string(text), "CANARY") {
		t.Fatal("cycle leaked")
	}
}

func TestTypedValuesAreHashedLikeTheirJSONForm(t *testing.T) {
	type mail struct {
		To []string `json:"to"`
	}
	typed := map[string]any{"m": mail{To: []string{"a@x.com"}}, "n": 3, "f": float32(1.5)}
	plainValue := map[string]any{"m": map[string]any{"to": []any{"a@x.com"}}, "n": float64(3), "f": 1.5}
	if canonicalJSON(HashArguments(typed, "s")) != canonicalJSON(HashArguments(plainValue, "s")) {
		t.Fatal("a typed value hashes as its JSON form")
	}
}

func TestPromptKeysAreSpellingInsensitive(t *testing.T) {
	out := TransformContext(map[string]any{"User_Message": "hi", "user-message": "yo", "task_id": "t-1", "nested": []any{map[string]any{"Prompt": "p"}}}, ModeDrop, "s")
	text, _ := json.Marshal(out)
	if string(text) != `{"nested":[{}],"task_id":"t-1"}` {
		t.Fatalf("%s", text)
	}
}

func clearEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{EnvToolArguments, EnvPrompts, EnvSalt, EnvLocalScan} {
		t.Setenv(name, "")
	}
}

func TestResolveDataHandling(t *testing.T) {
	clearEnv(t)
	if dh, err := ResolveDataHandling("", "", "", ""); dh != nil || err != nil {
		t.Fatalf("nothing configured must change nothing: %v %v", dh, err)
	}
	dh, err := ResolveDataHandling(" Hash ", "", "", "")
	if err != nil || dh == nil || dh.ToolArguments != ModeHash || dh.Prompts != "" || !dh.LocalScan || dh.Salt == "" {
		t.Fatalf("%+v %v", dh, err)
	}
	// Options win over the environment; the environment fills in.
	t.Setenv(EnvToolArguments, "redact")
	t.Setenv(EnvPrompts, "drop")
	t.Setenv(EnvSalt, "env-salt")
	t.Setenv(EnvLocalScan, "off")
	dh, err = ResolveDataHandling("", "", "", "")
	if err != nil || *dh != (DataHandling{ToolArguments: ModeRedact, Prompts: ModeDrop, Salt: "env-salt", LocalScan: false}) {
		t.Fatalf("%+v %v", dh, err)
	}
	dh, err = ResolveDataHandling("drop", "hash", "option-salt", "on")
	if err != nil || *dh != (DataHandling{ToolArguments: ModeDrop, Prompts: ModeHash, Salt: "option-salt", LocalScan: true}) {
		t.Fatalf("%+v %v", dh, err)
	}
}

func TestInvalidSettingsFailInsteadOfSendingValuesUnprotected(t *testing.T) {
	clearEnv(t)
	for name, args := range map[string][4]string{
		"misspelled mode": {"hasj", "", "", ""},
		"redact prompts":  {"", "redact", "", ""},
		"local scan":      {"hash", "", "", "maybe"},
	} {
		if dh, err := ResolveDataHandling(args[0], args[1], args[2], args[3]); err == nil || dh != nil {
			t.Errorf("%s: expected an error, got %+v", name, dh)
		} else if strings.Contains(err.Error(), "CANARY") {
			t.Errorf("%s: %v", name, err)
		}
	}
	t.Setenv(EnvToolArguments, "scramble")
	if _, err := ResolveDataHandling("", "", "", ""); err == nil || !strings.Contains(err.Error(), EnvToolArguments) {
		t.Errorf("an invalid environment value must fail, naming the variable: %v", err)
	}
	// An invalid local scan setting fails even when nothing else is configured.
	clearEnv(t)
	if _, err := ResolveDataHandling("", "", "", "sometimes"); err == nil {
		t.Error("an unclear local scan value must fail")
	}
}

func TestSaltIsPerProcessAndStable(t *testing.T) {
	if ProcessSalt() == "" || ProcessSalt() != ProcessSalt() || len(ProcessSalt()) != 64 {
		t.Fatal(ProcessSalt())
	}
	clearEnv(t)
	a, _ := ResolveDataHandling("hash", "", "", "")
	b, _ := ResolveDataHandling("hash", "", "", "")
	if a.Salt != b.Salt {
		t.Fatal("clients in one process share the default salt")
	}
	c, _ := ResolveDataHandling("hash", "", "fleet-salt", "")
	if c.Salt != "fleet-salt" {
		t.Fatal(c.Salt)
	}
}

func TestDeclarationNamesOnlyWhatWasApplied(t *testing.T) {
	got := (&DataHandling{ToolArguments: ModeHash}).Declaration()
	if canonicalJSON(got) != `{"applied_at":"client","tool_arguments":"hash","version":1}` {
		t.Fatal(canonicalJSON(got))
	}
	got = (&DataHandling{ToolArguments: ModeRedact, Prompts: ModeDrop}).Declaration()
	if canonicalJSON(got) != `{"applied_at":"client","prompts":"drop","tool_arguments":"redact","version":1}` {
		t.Fatal(canonicalJSON(got))
	}
	got = (&DataHandling{Prompts: ModeHash}).Declaration()
	if canonicalJSON(got) != `{"applied_at":"client","prompts":"hash","version":1}` {
		t.Fatal(canonicalJSON(got))
	}
}
