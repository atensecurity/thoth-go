package thoth

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Tool arguments reach the SDK as whatever the caller passed: map[string]any
// from a JSON decoder, but also typed slices, structs and named types. The data
// handling and the local scan read them through classify, one level at a time,
// so both see the same JSON-shaped view and neither depends on the Go type.

type nodeKind int

const (
	kindNull nodeKind = iota
	kindBool
	kindNumber
	kindString
	kindList
	kindObject
	// kindOther is a value with no JSON form (a channel, a function, NaN). Its
	// text is never the value itself.
	kindOther
)

type entry struct {
	key   string
	value any
}

type node struct {
	kind nodeKind
	// text is the string, the number as JSON writes it, "true" or "false", or
	// the description of an other value.
	text string
	list []any
	// obj is sorted by key (Unicode code point order), because a Go map has no
	// order and a deterministic walk matters more than insertion order.
	obj []entry
}

func classify(v any) node {
	switch x := v.(type) {
	case nil:
		return node{kind: kindNull}
	case string:
		return node{kind: kindString, text: x}
	case bool:
		return boolNode(x)
	case float64:
		return floatNode(x, 64)
	case float32:
		return floatNode(float64(x), 32)
	case int:
		return node{kind: kindNumber, text: strconv.FormatInt(int64(x), 10)}
	case int8:
		return node{kind: kindNumber, text: strconv.FormatInt(int64(x), 10)}
	case int16:
		return node{kind: kindNumber, text: strconv.FormatInt(int64(x), 10)}
	case int32:
		return node{kind: kindNumber, text: strconv.FormatInt(int64(x), 10)}
	case int64:
		return node{kind: kindNumber, text: strconv.FormatInt(x, 10)}
	case uint:
		return node{kind: kindNumber, text: strconv.FormatUint(uint64(x), 10)}
	case uint8:
		return node{kind: kindNumber, text: strconv.FormatUint(uint64(x), 10)}
	case uint16:
		return node{kind: kindNumber, text: strconv.FormatUint(uint64(x), 10)}
	case uint32:
		return node{kind: kindNumber, text: strconv.FormatUint(uint64(x), 10)}
	case uint64:
		return node{kind: kindNumber, text: strconv.FormatUint(x, 10)}
	case json.Number:
		return jsonNumberNode(x)
	case map[string]any:
		if x == nil {
			return node{kind: kindNull}
		}
		out := make([]entry, 0, len(x))
		for key, item := range x {
			out = append(out, entry{key, item})
		}
		sortEntries(out)
		return node{kind: kindObject, obj: out}
	case []any:
		if x == nil {
			return node{kind: kindNull}
		}
		return node{kind: kindList, list: x}
	}
	return classifyReflect(v)
}

func sortEntries(entries []entry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
}

func boolNode(b bool) node {
	if b {
		return node{kind: kindBool, text: "true"}
	}
	return node{kind: kindBool, text: "false"}
}

func floatNode(f float64, bits int) node {
	switch {
	case math.IsNaN(f):
		return node{kind: kindOther, text: "NaN"}
	case math.IsInf(f, 1):
		return node{kind: kindOther, text: "Infinity"}
	case math.IsInf(f, -1):
		return node{kind: kindOther, text: "-Infinity"}
	}
	return node{kind: kindNumber, text: floatText(f, bits)}
}

// floatText writes a finite float as JSON.stringify does: no exponent unless
// the magnitude is below 1e-6 or at least 1e21, and 0 for negative zero.
func floatText(f float64, bits int) string {
	if f == 0 {
		return "0"
	}
	format := byte('f')
	abs := math.Abs(f)
	if bits == 64 && (abs < 1e-6 || abs >= 1e21) || bits == 32 && (float32(abs) < 1e-6 || float32(abs) >= 1e21) {
		format = 'e'
	}
	b := strconv.AppendFloat(nil, f, format, -1, bits)
	if format == 'e' {
		// e-09 becomes e-9
		if n := len(b); n >= 4 && b[n-4] == 'e' && b[n-3] == '-' && b[n-2] == '0' {
			b[n-2] = b[n-1]
			b = b[:n-1]
		}
	}
	return string(b)
}

func jsonNumberNode(n json.Number) node {
	text := n.String()
	if i, err := strconv.ParseInt(text, 10, 64); err == nil {
		return node{kind: kindNumber, text: strconv.FormatInt(i, 10)}
	}
	if u, err := strconv.ParseUint(text, 10, 64); err == nil {
		return node{kind: kindNumber, text: strconv.FormatUint(u, 10)}
	}
	if f, err := strconv.ParseFloat(text, 64); err == nil {
		return floatNode(f, 64)
	}
	return node{kind: kindOther, text: "number"}
}

var (
	jsonMarshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	textMarshalerType = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
)

func classifyReflect(v any) node {
	rv := reflect.ValueOf(v)
	t := rv.Type()
	if t.Implements(jsonMarshalerType) || t.Implements(textMarshalerType) {
		return classifyMarshaled(v)
	}
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return node{kind: kindNull}
		}
		return classify(rv.Elem().Interface())
	case reflect.Bool:
		return boolNode(rv.Bool())
	case reflect.String:
		return node{kind: kindString, text: rv.String()}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return node{kind: kindNumber, text: strconv.FormatInt(rv.Int(), 10)}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return node{kind: kindNumber, text: strconv.FormatUint(rv.Uint(), 10)}
	case reflect.Float32:
		return floatNode(rv.Float(), 32)
	case reflect.Float64:
		return floatNode(rv.Float(), 64)
	case reflect.Map:
		if rv.IsNil() {
			return node{kind: kindNull}
		}
		out := make([]entry, 0, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			key := iter.Key()
			name := ""
			if key.Kind() == reflect.String {
				name = key.String()
			} else {
				name = fmt.Sprint(key.Interface())
			}
			out = append(out, entry{name, iter.Value().Interface()})
		}
		sortEntries(out)
		return node{kind: kindObject, obj: out}
	case reflect.Slice:
		if rv.IsNil() {
			return node{kind: kindNull}
		}
		if t.Elem().Kind() == reflect.Uint8 {
			return classifyMarshaled(v) // []byte is base64 text in JSON
		}
		return listNode(rv)
	case reflect.Array:
		return listNode(rv)
	case reflect.Struct:
		return classifyMarshaled(v)
	}
	return node{kind: kindOther, text: fmt.Sprintf("%T", v)}
}

func listNode(rv reflect.Value) node {
	items := make([]any, rv.Len())
	for i := range items {
		items[i] = rv.Index(i).Interface()
	}
	return node{kind: kindList, list: items}
}

// classifyMarshaled reads a value through its JSON form (struct tags, MarshalJSON).
func classifyMarshaled(v any) node {
	raw, err := json.Marshal(v)
	if err != nil {
		// The error text could quote the value; the type name cannot.
		return node{kind: kindOther, text: fmt.Sprintf("%T", v)}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return node{kind: kindOther, text: fmt.Sprintf("%T", v)}
	}
	return classify(generic)
}

// canonicalMaxDepth and canonicalMaxNodes only guard against a cyclic or
// enormous value reaching the canonical writer; hashed leaves are scalars, and
// a prompt value that deep is hashed with the marker in place of the rest.
const (
	canonicalMaxDepth = 100
	canonicalMaxNodes = 100000
)

// canonicalJSON is the byte form that is hashed: keys sorted by code point, no
// spaces, non-ASCII and <, >, & not escaped, numbers as JSON.stringify writes them.
func canonicalJSON(v any) string {
	var sb strings.Builder
	budget := canonicalMaxNodes
	writeCanonical(&sb, v, 0, &budget)
	return sb.String()
}

func writeCanonical(sb *strings.Builder, v any, depth int, budget *int) {
	if depth > canonicalMaxDepth || *budget <= 0 {
		writeJSONString(sb, TruncatedMarker)
		return
	}
	*budget--
	n := classify(v)
	switch n.kind {
	case kindNull:
		sb.WriteString("null")
	case kindBool, kindNumber:
		sb.WriteString(n.text)
	case kindString, kindOther:
		writeJSONString(sb, n.text)
	case kindList:
		sb.WriteByte('[')
		for i, item := range n.list {
			if i > 0 {
				sb.WriteByte(',')
			}
			writeCanonical(sb, item, depth+1, budget)
		}
		sb.WriteByte(']')
	case kindObject:
		sb.WriteByte('{')
		for i, item := range n.obj {
			if i > 0 {
				sb.WriteByte(',')
			}
			writeJSONString(sb, item.key)
			sb.WriteByte(':')
			writeCanonical(sb, item.value, depth+1, budget)
		}
		sb.WriteByte('}')
	}
}

const hexDigits = "0123456789abcdef"

// writeJSONString escapes a string as JSON requires and nothing more. Go's
// encoding/json also writes U+2028 and U+2029 as escapes, which Python and
// JavaScript do not, so it is not used here.
func writeJSONString(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			sb.WriteString(`\"`)
		case r == '\\':
			sb.WriteString(`\\`)
		case r == '\b':
			sb.WriteString(`\b`)
		case r == '\f':
			sb.WriteString(`\f`)
		case r == '\n':
			sb.WriteString(`\n`)
		case r == '\r':
			sb.WriteString(`\r`)
		case r == '\t':
			sb.WriteString(`\t`)
		case r < 0x20:
			sb.WriteString(`\u00`)
			sb.WriteByte(hexDigits[r>>4])
			sb.WriteByte(hexDigits[r&0xf])
		case r == utf8.RuneError:
			// Invalid bytes and a real U+FFFD both become U+FFFD, as encoding/json does.
			sb.WriteRune(utf8.RuneError)
		default:
			sb.WriteRune(r)
		}
	}
	sb.WriteByte('"')
}
