package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Decode decodes exactly one JSON value and rejects unknown fields and trailing data.
func Decode(r io.Reader, dst any) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode JSON: trailing value")
		}
		return fmt.Errorf("decode JSON trailing data: %w", err)
	}
	return nil
}

func DecodeBytes(data []byte, dst any) error { return Decode(bytes.NewReader(data), dst) }

func DecodeFile(path string, dst any) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	return Decode(f, dst)
}

func MarshalCanonical(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical JSON: %w", err)
	}
	return b, nil
}
