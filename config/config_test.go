package config

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestDefaultRoundTrip(t *testing.T) {
	value := Default()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	classifier, err := decoded.Classifier()
	if err != nil || classifier == nil {
		t.Fatalf("classifier=%v err=%v", classifier, err)
	}
}

func TestDecodeIsStrict(t *testing.T) {
	value := Default()
	data, _ := json.Marshal(value)
	var object map[string]any
	_ = json.Unmarshal(data, &object)
	object["unknown"] = true
	data, _ = json.Marshal(object)
	if _, err := Decode(bytes.NewReader(data)); err == nil {
		t.Fatal("unknown field was accepted")
	}
	valid, _ := json.Marshal(Default())
	valid = append(valid, []byte(` {}`)...)
	if _, err := Decode(bytes.NewReader(valid)); err == nil {
		t.Fatal("trailing value was accepted")
	}
}

func TestValidationRejectsUnsafeValues(t *testing.T) {
	cases := []Config{Default(), Default(), Default(), Default()}
	cases[0].Version = 2
	cases[1].Classification.MinSeverity = "severe"
	cases[2].Limits.MaxPolicyBytes = 0
	cases[3].Classification.AllowPatterns = []string{"["}
	for index, value := range cases {
		if err := value.Validate(); err == nil {
			t.Fatalf("case %d was accepted", index)
		}
	}
}
