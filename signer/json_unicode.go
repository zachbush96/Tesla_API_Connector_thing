package restricted

import "unicode/utf8"

// encoding/json replaces invalid UTF-8 and unmatched escaped surrogates with
// U+FFFD. Refuse those encodings before decoding so an exact command cannot be
// silently changed. A literal U+FFFD and correctly paired escapes remain valid.
// strictJSON independently validates grammar, duplicate keys and object fields.
func jsonUnicodeScalars(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	quoted := false
	for n := 0; n < len(raw); n++ {
		if raw[n] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || raw[n] != '\\' {
			continue
		}
		n++
		if n >= len(raw) {
			return false
		}
		// Escaped quotes and backslashes are skipped, including literal \\u text.
		if raw[n] != 'u' {
			continue
		}
		if n+4 >= len(raw) {
			return false
		}
		first, ok := jsonHexCodeUnit(raw[n+1 : n+5])
		if !ok {
			return false
		}
		n += 4
		if first >= 0xD800 && first <= 0xDBFF {
			if n+6 >= len(raw) || raw[n+1] != '\\' || raw[n+2] != 'u' {
				return false
			}
			second, ok := jsonHexCodeUnit(raw[n+3 : n+7])
			if !ok || second < 0xDC00 || second > 0xDFFF {
				return false
			}
			n += 6
		} else if first >= 0xDC00 && first <= 0xDFFF {
			return false
		}
	}
	return !quoted
}

func jsonHexCodeUnit(raw []byte) (uint16, bool) {
	if len(raw) != 4 {
		return 0, false
	}
	var value uint16
	for _, c := range raw {
		value <<= 4
		switch {
		case c >= '0' && c <= '9':
			value |= uint16(c - '0')
		case c >= 'a' && c <= 'f':
			value |= uint16(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			value |= uint16(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return value, true
}
