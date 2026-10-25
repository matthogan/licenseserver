package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSpecifiedCommandTreeIsPresent(t *testing.T) {
	root := rootCmd()
	for _, path := range [][]string{
		{"product", "update"}, {"trial", "show"}, {"licence", "reissue"},
		{"backup", "list"}, {"audit", "export"}, {"maintenance", "enable"},
		{"maintenance", "disable"}, {"db", "migrate"}, {"archive", "reconcile"},
		{"root", "keyring"}, {"root", "transition", "generate"}, {"root", "transition", "inspect"},
		{"root", "transition", "verify"}, {"root", "transition", "activate"}, {"root", "transition", "retire"},
		{"root", "transition", "rollback"},
		{"data", "export"},
		{"data", "retention", "policy", "set"}, {"data", "retention", "plan"},
		{"data", "retention", "apply"}, {"data", "delete"}, {"data", "hold", "create"},
		{"data", "hold", "release"}, {"data", "tombstones", "list"},
		{"recovery-drill", "run"}, {"recovery-drill", "status"},
		{"recovery-drill", "list"}, {"recovery-drill", "show"},
	} {
		command, _, err := root.Find(path)
		if err != nil || command == root || command.Name() != path[len(path)-1] {
			t.Fatalf("missing command %v: command=%q err=%v", path, command.Name(), err)
		}
	}
}

func TestCommitDataExportExclusiveNeverOverwrites(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "export.tar.gz")
	first := filepath.Join(directory, "first.tmp")
	if err := os.WriteFile(first, []byte("first-export"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := commitDataExportExclusive(first, destination); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(directory, "second.tmp")
	if err := os.WriteFile(second, []byte("second-export"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := commitDataExportExclusive(second, destination); err == nil {
		t.Fatal("existing export was overwritten")
	}
	content, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "first-export" {
		t.Fatalf("destination=%q", content)
	}
}
