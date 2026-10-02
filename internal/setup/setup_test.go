package setup

import (
	"os"
	"path/filepath"
	"testing"
)

// S1: the reports folder exists after setup, even when no report is made
// (an upgrade), so "Open reports folder" opens it.
func TestEnsureDir(t *testing.T) {
	d := filepath.Join(t.TempDir(), "Blackbox", "reports")
	if err := ensureDir(d); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
		t.Errorf("reports folder not made: %v", err)
	}
	if err := ensureDir(d); err != nil {
		t.Errorf("an existing folder: %v", err)
	}
}
