package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCommittedVectorIsDeterministicallyGenerated(t *testing.T) {
	committed, err := os.ReadFile("../../../docs/licence-test-vector-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(t.TempDir(), "licence-test-vector-v1.json")
	if err = os.WriteFile(temporary, committed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = generate(temporary); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(temporary)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(committed, first) {
		t.Fatal("committed vector does not match deterministic generator output")
	}
	if err = generate(temporary); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(temporary)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("repeated generation changed vector bytes")
	}
}
