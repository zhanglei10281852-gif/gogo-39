package model

import (
	"encoding/json"
	"testing"
)

func TestToolCallValidateRejectsNullArguments(t *testing.T) {
	call := ToolCall{
		ID:         "call-1",
		Tool:       "example-tool",
		Operation:  "read",
		Capability: "example:read",
		Arguments:  json.RawMessage("null"),
	}

	if err := call.Validate(); err == nil {
		t.Fatal("ToolCall.Validate() error = nil, want validation error for null arguments")
	}
}
