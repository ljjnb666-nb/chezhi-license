package main

import (
	"context"
	"os"
	"testing"
)

func TestCommandOptionProbesDoNotInitialize(t *testing.T) {
	// Isolate the legacy relative data directory. This test is deliberately
	// non-parallel because the process working directory is shared.
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(old); err != nil {
			t.Error(err)
		}
	})
	t.Setenv("CHEZHI_MODE", "local")
	t.Setenv("CHEZHI_STORAGE", "json")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		args []string
		wantErr bool
	}{
		{[]string{"-h"}, false},
		{[]string{"--help"}, false},
		{[]string{"--unknown"}, true},
		{[]string{"--help", "extra"}, true},
	} {
		if err := run(ctx, tc.args); (err != nil) != tc.wantErr {
			t.Fatalf("run(%q): %v", tc.args, err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("option probe created state: %v, %v", entries, err)
		}
	}
}
