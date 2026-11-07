package server

import (
	"os"
	"testing"
)

func TestLegacyDynamoTable(t *testing.T) {
	t.Setenv("dynamodb_table_legacy", "")
	if got := legacyDynamoTable(); got != "" {
		t.Errorf("empty value: got %q want \"\"", got)
	}

	if err := os.Unsetenv("dynamodb_table_legacy"); err != nil {
		t.Fatal(err)
	}
	if got := legacyDynamoTable(); got != "redemptions" {
		t.Errorf("unset: got %q want \"redemptions\"", got)
	}
}
