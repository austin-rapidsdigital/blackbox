package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

func TestSpoolAndState(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	if err := s.AppendEvents(now, []*event.Event{{Time: now, Summary: "a"}, {Time: now, Summary: "b"}}); err != nil {
		t.Fatal(err)
	}
	s.State.Bookmarks[BookmarkKey("ws-07", "Security")] = Bookmark{RecordID: 42}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	// A torn final line (power loss mid-write) must not break reading.
	f, _ := os.OpenFile(filepath.Join(dir, "spool", "events-2026-09-29.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"time":"2026-09-29T10:0`)
	f.Close()

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.State.Bookmarks["WS-07|Security"].RecordID != 42 {
		t.Error("bookmark not persisted")
	}
	ev, err := s2.ReadEvents(time.Time{})
	if err != nil || len(ev) != 2 {
		t.Fatalf("read %d events, err %v", len(ev), err)
	}
}

func TestLock(t *testing.T) {
	s, _ := Open(t.TempDir())
	unlock, err := s.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lock(); err == nil {
		t.Error("second lock should fail")
	}
	unlock()
	if u, err := s.Lock(); err != nil {
		t.Error("lock after unlock should succeed")
	} else {
		u()
	}
}
