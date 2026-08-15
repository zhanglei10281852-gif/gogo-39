package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"agentguard/model"
)

// Canonicalize validates one JSON value, rejects duplicate object names, and
// emits a whitespace-free representation with sorted object names.
func Canonicalize(input []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	value, err := decodeCanonicalValue(dec)
	if err != nil {
		return nil, err
	}
	if token, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("audit: unexpected token %v after JSON value", token)
		}
		return nil, fmt.Errorf("audit: trailing JSON: %w", err)
	}
	var out bytes.Buffer
	if err := writeCanonical(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// CanonicalJSON marshals v and canonicalizes the resulting JSON. Maps are
// ordered by UTF-8 object-name bytes and HTML characters are not escaped.
func CanonicalJSON(v any) ([]byte, error) {
	var source []byte
	if raw, ok := v.(json.RawMessage); ok {
		source = raw
	} else {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			return nil, fmt.Errorf("audit: encode JSON: %w", err)
		}
		source = buf.Bytes()
	}
	return Canonicalize(source)
}
func decodeCanonicalValue(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("audit: invalid JSON: %w", err)
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for dec.More() {
				nameToken, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("audit: invalid object name: %w", err)
				}
				name, ok := nameToken.(string)
				if !ok {
					return nil, errors.New("audit: object name is not a string")
				}
				if _, exists := object[name]; exists {
					return nil, fmt.Errorf("audit: duplicate object name %q", name)
				}
				member, err := decodeCanonicalValue(dec)
				if err != nil {
					return nil, err
				}
				object[name] = member
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errors.New("audit: unterminated object")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for dec.More() {
				member, err := decodeCanonicalValue(dec)
				if err != nil {
					return nil, err
				}
				array = append(array, member)
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errors.New("audit: unterminated array")
			}
			return array, nil
		default:
			return nil, fmt.Errorf("audit: unexpected delimiter %q", value)
		}
	case string, bool, nil, json.Number:
		return value, nil
	default:
		return nil, fmt.Errorf("audit: unsupported JSON token %T", value)
	}
}

func writeCanonical(out *bytes.Buffer, value any) error {
	switch value := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if value {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		writeJSONString(out, value)
	case json.Number:
		number, err := canonicalNumber(string(value))
		if err != nil {
			return err
		}
		out.WriteString(number)
	case []any:
		out.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonical(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			writeJSONString(out, key)
			out.WriteByte(':')
			if err := writeCanonical(out, value[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("audit: unsupported canonical value %T", value)
	}
	return nil
}
func writeJSONString(out *bytes.Buffer, value string) {
	encoded, _ := json.Marshal(value)
	// encoding/json only introduces these HTML escapes beyond JSON's required
	// escapes. Replacing them preserves valid JSON and avoids context variance.
	text := string(encoded)
	text = strings.ReplaceAll(text, `\u003c`, "<")
	text = strings.ReplaceAll(text, `\u003e`, ">")
	text = strings.ReplaceAll(text, `\u0026`, "&")
	out.WriteString(text)
}

func canonicalNumber(text string) (string, error) {
	value, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(value, 0) || math.IsNaN(value) {
		return "", fmt.Errorf("audit: invalid JSON number %q", text)
	}
	if value == 0 {
		return "0", nil
	}
	result := strconv.FormatFloat(value, 'g', -1, 64)
	if index := strings.IndexByte(result, 'e'); index >= 0 {
		mantissa, exponent := result[:index], result[index+1:]
		sign := ""
		if strings.HasPrefix(exponent, "+") {
			exponent = exponent[1:]
		} else if strings.HasPrefix(exponent, "-") {
			sign, exponent = "-", exponent[1:]
		}
		exponent = strings.TrimLeft(exponent, "0")
		if exponent == "" {
			exponent = "0"
		}
		result = mantissa + "e" + sign + exponent
	}
	return result, nil
}

func digestHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// EventHash computes the event hash over all fields except Hash. Payload is
// canonicalized first, making semantically equivalent object key order stable.
func EventHash(event model.AuditEvent) (string, error) {
	payload, err := Canonicalize(event.Payload)
	if err != nil {
		return "", fmt.Errorf("audit: event payload: %w", err)
	}
	body := struct {
		Sequence     uint64          `json:"sequence"`
		Timestamp    time.Time       `json:"timestamp"`
		Type         string          `json:"type"`
		RequestID    string          `json:"request_id,omitempty"`
		SessionID    string          `json:"session_id,omitempty"`
		ActorID      string          `json:"actor_id,omitempty"`
		PolicyID     string          `json:"policy_id,omitempty"`
		Payload      json.RawMessage `json:"payload"`
		PreviousHash string          `json:"previous_hash"`
	}{
		Sequence: event.Sequence, Timestamp: event.Timestamp, Type: event.Type,
		RequestID: event.RequestID, SessionID: event.SessionID,
		ActorID: event.ActorID, PolicyID: event.PolicyID,
		Payload: payload, PreviousHash: event.PreviousHash,
	}
	canonical, err := CanonicalJSON(body)
	if err != nil {
		return "", err
	}
	return digestHex(canonical), nil
}
