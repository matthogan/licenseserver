package signing

import (
	"errors"
	"testing"
)

func TestFailedTransitionPreservesActiveSigner(t *testing.T) {
	manager := NewManager(&Local{keyID: "old"})
	want := errors.New("persistence failed")
	err := manager.Transition(&Local{keyID: "new"}, func() error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("got %v", err)
	}
	if current, ok := manager.Current(); !ok || current != "old" {
		t.Fatalf("current=%q ok=%v", current, ok)
	}
}
