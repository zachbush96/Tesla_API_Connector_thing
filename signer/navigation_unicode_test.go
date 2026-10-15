package restricted

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func navigationUnicodePayload(destinationJSON string) string {
	return fmt.Sprintf(`{"locale":"en-US","timestamp_ms":"1791650000000","type":"share_ext_content_raw","value":{"android.intent.ACTION":"android.intent.action.SEND","android.intent.TEXT":%s,"android.intent.TYPE":"text/plain","android.intent.extra.TEXT":%s}}`, destinationJSON, destinationJSON)
}

func navigationUnicodeString(value string) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func TestNavigationUnicodeCharacterBounds(t *testing.T) {
	cases := []struct {
		name, destination string
		accepted          bool
	}{
		{"ascii_300", strings.Repeat("A", 300), true},
		{"ascii_301", strings.Repeat("A", 301), false},
		{"supplementary_151", strings.Repeat("\U0001F697", 151), true},
		{"supplementary_300", strings.Repeat("\U0001F697", 300), true},
		{"supplementary_301", strings.Repeat("\U0001F697", 301), false},
		{"mixed_300", strings.Repeat("A", 150) + strings.Repeat("\U0001F697", 150), true},
		{"mixed_301", strings.Repeat("A", 151) + strings.Repeat("\U0001F697", 150), false},
		{"replacement_scalar", "\uFFFD", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, _, err := parseIntent(rawIntent("navigation_send", navigationUnicodePayload(navigationUnicodeString(c.destination))))
			if (err == nil) != c.accepted {
				t.Fatal("navigation scalar bound disagrees with public schema")
			}
		})
	}
}

func TestNavigationJSONUnicodeScalars(t *testing.T) {
	cases := []struct {
		name, destinationJSON string
		accepted              bool
	}{
		{"paired_escape", `"\ud83d\ude97"`, true},
		{"paired_escaped_300", `"` + strings.Repeat(`\ud83d\ude97`, 300) + `"`, true},
		{"escaped_backslash_literal", `"\\ud800"`, true},
		{"escaped_quote_and_backslash", navigationUnicodeString(`Synthetic "quoted" \\path`), true},
		{"lone_high", `"\ud800"`, false},
		{"lone_low", `"\udfff"`, false},
		{"high_then_plain", `"\ud800A"`, false},
		{"high_then_high", `"\ud800\ud800"`, false},
		{"low_then_high", `"\udfff\ud800"`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, _, err := parseIntent(rawIntent("navigation_send", navigationUnicodePayload(c.destinationJSON)))
			if (err == nil) != c.accepted {
				t.Fatal("navigation JSON Unicode scalar policy disagrees")
			}
		})
	}
}

func TestStrictJSONInvalidUTF8Refused(t *testing.T) {
	for _, invalid := range [][]byte{{0xff}, {0xc0, 0xaf}, {0xed, 0xa0, 0x80}} {
		raw := append([]byte(`{"destination":"`), invalid...)
		raw = append(raw, []byte(`"}`)...)
		var value map[string]any
		if strictJSON(raw, &value) == nil {
			t.Fatal("invalid UTF-8 accepted by strict JSON boundary")
		}
	}
}

func TestStrictJSONUnicodeEscapeBoundaries(t *testing.T) {
	cases := []struct {
		name, raw string
		accepted  bool
	}{
		{"escaped_replacement_scalar", `{"value":"\ufffd"}`, true},
		{"quote_then_literal_backslash_u", `{"value":"quote \" then \\ud800"}`, true},
		{"odd_backslashes_then_unmatched_escape", `{"value":"\\\ud800"}`, false},
		{"valid_pair_then_lone_low", `{"value":"\ud83d\ude97\udfff"}`, false},
		{"surrogate_in_object_key", `{"\ud800":"value"}`, false},
		{"nested_key_and_value_pair", `{"nested":{"\ud83d\ude97":["\ud83d\ude97"]}}`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var value map[string]any
			if (strictJSON([]byte(c.raw), &value) == nil) != c.accepted {
				t.Fatal("JSON string encoding boundary disagrees")
			}
		})
	}
}

func TestLocalSignerNavigationUnicodeSimulationAndReplay(t *testing.T) {
	for _, c := range []struct {
		name, destinationJSON string
		accepted              bool
	}{
		{"ascii_300", navigationUnicodeString(strings.Repeat("A", 300)), true},
		{"ascii_301", navigationUnicodeString(strings.Repeat("A", 301)), false},
		{"supplementary_300", navigationUnicodeString(strings.Repeat("\U0001F697", 300)), true},
		{"supplementary_301", navigationUnicodeString(strings.Repeat("\U0001F697", 301)), false},
		{"python_escaped_supplementary_300", `"` + strings.Repeat(`\ud83d\ude97`, 300) + `"`, true},
		{"lone_high", `"\ud800"`, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := testService(t)
			body := simulateRequest(rawIntent("navigation_send", navigationUnicodePayload(c.destinationJSON)), strings.Repeat("a", 32))
			w := serviceRequest(s, "POST", "/simulate", body, true)
			if !c.accepted {
				if w.Code != 403 || len(s.used) != 0 {
					t.Fatal("invalid navigation was not refused before simulation claim")
				}
				return
			}
			var value map[string]any
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &value) != nil || value["action"] != "navigation_send" || value["simulated"] != true || value["executed"] != false || value["execution_enabled"] != false || value["synthetic_sdk_requests"] != float64(1) || value["fleet_network_requests"] != float64(0) || value["gross_reserved_microdollars"] != float64(0) {
				t.Fatal("full SDK mock navigation did not complete with zero Fleet requests and cost")
			}
			if serviceRequest(s, "POST", "/simulate", body, true).Code != 409 || len(s.used) != 1 {
				t.Fatal("SDK mock navigation replay was not refused")
			}
		})
	}
}
