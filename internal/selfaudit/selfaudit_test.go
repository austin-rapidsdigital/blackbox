package selfaudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

func TestChanges(t *testing.T) {
	got := Changes(map[string]string{"retention_days": "365", "site_name": "Lab", "inbox": ""},
		map[string]string{"retention_days": "30", "site_name": "Lab", "inbox": `C:\Inbox`}, "setup")
	if len(got) != 2 || got[0].Setting != "inbox" || got[1].Setting != "retention_days" || got[1].Old != "365" || got[1].New != "30" {
		t.Errorf("changes: %+v", got)
	}
}

// A15: the change is in the spool even if the system log can't be
// written (no syslog socket in a container).
func TestRecordWritesSpool(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	Record(dir, event.SelfChange{Kind: "setting", Setting: "send_to", Old: "", New: "/mnt/inbox", Who: "claude", Program: "blackbox config set"}, now)
	files, _ := filepath.Glob(filepath.Join(dir, "spool", "events-*.jsonl"))
	if len(files) != 1 {
		t.Fatalf("spool files: %v", files)
	}
	b, _ := os.ReadFile(files[0])
	if !strings.Contains(string(b), `"action":"blackbox_config_changed"`) || !strings.Contains(string(b), "changed Blackbox's send_to setting") {
		t.Errorf("spool: %s", b)
	}
}
