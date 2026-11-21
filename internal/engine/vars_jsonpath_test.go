package engine

// vars_jsonpath_test.go — benchmarks and behavior checks for JSON path
// extraction. The scalar fast path must produce exactly the same text as
// fmt.Sprintf("%v", value) for every value the JSON decoder can produce.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func BenchmarkExtractJSONPath(b *testing.B) {
	body := []byte(`{"id":42,"name":"widget","active":true,"score":3.5,"nested":{"value":7},"tags":["a","b"]}`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = extractJSONPath(body, "name")
	}
}

// jsonPathReference is the original formatting rule, kept as an oracle so the
// scalar fast path can be checked against every scalar kind after decoding.
func jsonPathReference(body []byte, path string) (string, error) {
	value, err := extractJSONPathWithFmt(body, path)
	return value, err
}

// extractJSONPathWithFmt mirrors extractJSONPath but always formats the final
// value with fmt.Sprintf, matching the implementation before the fast path.
func extractJSONPathWithFmt(body []byte, path string) (string, error) {
	var value interface{}
	if err := json.Unmarshal(body, &value); err != nil {
		return "", err
	}
	cur := value
	for _, part := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("path %q not found", path)
		}
		cur, ok = obj[part]
		if !ok || cur == nil {
			return "", fmt.Errorf("path %q not found", path)
		}
	}
	return fmt.Sprintf("%v", cur), nil
}

func TestExtractJSONPathMatchesFmtReference(t *testing.T) {
	bodies := []string{
		`{"s":"hello","n":42,"f":3.5,"big":1e20,"neg":-0,"t":true,"off":false,"arr":[1,"x",true],"obj":{"k":"v"},"nest":{"deep":{"v":9}}}`,
		`{"f":0,"g":1e-7,"h":-12345.6789,"i":9007199254740993}`,
		`{"empty":"","zero":0,"exp":1e+06}`,
	}
	paths := []string{"s", "n", "f", "big", "neg", "t", "off", "arr", "obj", "nest.deep.v", "empty", "zero", "exp", "g", "h", "i", "missing"}
	for _, raw := range bodies {
		for _, path := range paths {
			want, wantErr := jsonPathReference([]byte(raw), path)
			got, gotErr := extractJSONPath([]byte(raw), path)
			if (wantErr == nil) != (gotErr == nil) {
				t.Fatalf("body %s path %s: error mismatch: ref=%v got=%v", raw, path, wantErr, gotErr)
			}
			if got != want {
				t.Errorf("body %s path %s: got %q, reference %q", raw, path, got, want)
			}
		}
	}
}
