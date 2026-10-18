package connectorsdk

import (
	"os"
	"strings"
	"testing"
)

func TestSharedFixturePreservesLargeDecimalOrderAndUTF8(t *testing.T) {
	raw, err := os.ReadFile("../fixtures/events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ValidateJSONL(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(rows[0].Value.Order) != `"9007199254740993"` {
		t.Fatalf("order was rounded/changed: %s", rows[0].Value.Order)
	}
	if string(rows[0].Payload) != "Hola, mundo 🌎" {
		t.Fatalf("payload changed: %q", rows[0].Payload)
	}
	if string(rows[0].Bytes) != strings.SplitAfter(string(raw), "\n")[0] {
		t.Fatal("raw event bytes changed")
	}
	plan, err := Plan(raw)
	if err != nil || plan["events"] != 2 {
		t.Fatalf("plan: %#v %v", plan, err)
	}
}
func TestRejectsNumericOrderAndBadDigest(t *testing.T) {
	raw, _ := os.ReadFile("../fixtures/events.jsonl")
	numeric := strings.Replace(string(raw), `"order":"9007199254740993"`, `"order":9007199254740993`, 1)
	if _, err := ValidateJSONL([]byte(numeric)); err == nil {
		t.Fatal("accepted numeric order")
	}
	corrupted := strings.Replace(string(raw), "2fb57883", "0fb57883", 1)
	if _, err := ValidateJSONL([]byte(corrupted)); err == nil {
		t.Fatal("accepted digest mismatch")
	}
}
