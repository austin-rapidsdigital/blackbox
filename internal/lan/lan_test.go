package lan

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

var t0 = time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)

// system is a data folder with some collected data, like one computer.
func system(t *testing.T, host, osName string, n int, at time.Time) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	collect(t, st, host, osName, n, at)
	return st
}

// collect adds n events, a run and a check, as one collection would.
func collect(t *testing.T, st *store.Store, host, osName string, n int, at time.Time) {
	t.Helper()
	var evs []*event.Event
	for i := 0; i < n; i++ {
		evs = append(evs, &event.Event{Time: at.Add(-time.Duration(i) * time.Minute), Collected: at, Host: host, OS: osName,
			Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "logon"})
	}
	if err := st.AppendEvents(at, evs); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendRun(&store.Run{Time: at, Host: host, OS: osName, Version: "test",
		Channels: []store.ChannelRun{{Channel: "Security", Read: n, Kept: n}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendChecks(&store.CheckRecord{Time: at, Host: host, OS: osName,
		Results: []check.Result{{Area: "Audit policy", Item: "Logon", Status: check.Pass}}}); err != nil {
		t.Fatal(err)
	}
}

func inbox(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := PrepareInbox(dir, "COLLECTOR"); err != nil {
		t.Fatal(err)
	}
	return dir
}

func send(t *testing.T, st *store.Store, host, dir string, at time.Time) int {
	t.Helper()
	if _, err := Export(st, host, "test", at); err != nil {
		t.Fatal(err)
	}
	n, err := Deliver(st, dir, host)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestBatchRoundTripAndTamperDetection(t *testing.T) {
	b := &Batch{Header: Header{Sender: "WS-01", SenderID: "abc", Seq: 7, Created: t0},
		Events: [][]byte{[]byte(`{"host":"WS-01","summary":"one"}`)}, Runs: [][]byte{[]byte(`{"host":"WS-01"}`)}}
	data, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if got.Seq != 7 || got.Sender != "WS-01" || len(got.Events) != 1 || len(got.Runs) != 1 || string(got.Events[0]) != `{"host":"WS-01","summary":"one"}` {
		t.Fatalf("round trip lost data: %+v", got)
	}

	// Cut short: no trailer.
	if _, err := Decode(bytes.NewReader(data[:len(data)/2])); err == nil {
		t.Error("a truncated batch was accepted")
	}
	// Altered contents with the original trailer.
	b.Events[0] = []byte(`{"host":"WS-01","summary":"two"}`)
	altered, _ := b.Bytes()
	if _, err := Decode(bytes.NewReader(spliceTrailer(t, altered, data))); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Errorf("altered batch: got %v, want a checksum error", err)
	}
	if _, err := Decode(strings.NewReader("hello")); err == nil {
		t.Error("a non-batch file was accepted")
	}
}

// spliceTrailer puts the original batch's trailer on the altered batch.
func spliceTrailer(t *testing.T, altered, original []byte) []byte {
	t.Helper()
	lines := func(b []byte) []string {
		raw, err := gunzip(b)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	}
	a, o := lines(altered), lines(original)
	a[len(a)-1] = o[len(o)-1]
	return gzipBytes(t, strings.Join(a, "\n")+"\n")
}

func TestSendAndImport(t *testing.T) {
	in := inbox(t)
	ws := system(t, "WS-01", "windows", 3, t0)
	vm := system(t, "ubuntu-vm", "linux", 2, t0)
	if n := send(t, ws, "WS-01", in, t0); n != 1 {
		t.Fatalf("sent %d batches, want 1", n)
	}
	send(t, vm, "ubuntu-vm", in, t0)
	if Queued(ws) != 0 {
		t.Error("outbox not emptied after delivery")
	}

	col, _ := store.Open(t.TempDir())
	now := t0.Add(30 * time.Minute)
	res, err := Import(col, in, now, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if res.Batches != 2 || len(res.Rejected) != 0 {
		t.Fatalf("imported %+v", res)
	}
	evs, _ := col.ReadEvents(time.Time{})
	if len(evs) != 5 {
		t.Fatalf("collector has %d events, want 5", len(evs))
	}
	for _, e := range evs {
		if !e.Collected.Equal(now) {
			t.Errorf("received event should count as collected on arrival, got %v", e.Collected)
		}
	}
	runs, _ := col.ReadRuns(time.Time{})
	if len(runs) != 2 || !runs[0].Received.Equal(now) {
		t.Errorf("runs not imported with their arrival time: %+v", runs)
	}
	checks, _ := col.LatestChecks(time.Time{}, now)
	if len(checks) != 2 || checks["UBUNTU-VM"] == nil {
		t.Errorf("audit checks not imported: %v", checks)
	}
	sys := col.State.Systems["UBUNTU-VM"]
	if sys == nil || sys.OS != "linux" || !sys.LastRun.Equal(t0) || !sys.LastReceived.Equal(now) {
		t.Errorf("system registry: %+v", sys)
	}
	left, _ := filepath.Glob(filepath.Join(in, "*.bbx"))
	if len(left) != 0 {
		t.Errorf("imported batches left in the inbox: %v", left)
	}

	// Next hour: only new data travels.
	collect(t, ws, "WS-01", "windows", 1, t0.Add(time.Hour))
	send(t, ws, "WS-01", in, t0.Add(time.Hour))
	res, _ = Import(col, in, now.Add(time.Hour), t.Logf)
	if res.Records != 3 { // 1 event, 1 run, 1 check
		t.Errorf("second import had %d records, want 3 (nothing re-sent)", res.Records)
	}
}

func TestDuplicateDeliveryAndMissingBatch(t *testing.T) {
	in := inbox(t)
	ws := system(t, "WS-01", "windows", 1, t0)
	Export(ws, "WS-01", "test", t0) // batch 1
	collect(t, ws, "WS-01", "windows", 1, t0.Add(time.Hour))
	Export(ws, "WS-01", "test", t0.Add(time.Hour)) // batch 2
	collect(t, ws, "WS-01", "windows", 1, t0.Add(2*time.Hour))
	Export(ws, "WS-01", "test", t0.Add(2*time.Hour)) // batch 3
	if _, err := Deliver(ws, in, "WS-01"); err != nil {
		t.Fatal(err)
	}
	id := ws.State.Send.ID
	one := filepath.Join(in, InboxName("WS-01", id, 1))
	saved, _ := os.ReadFile(one)
	os.Remove(filepath.Join(in, InboxName("WS-01", id, 2))) // lost in transit

	col, _ := store.Open(t.TempDir())
	if _, err := Import(col, in, t0.Add(3*time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	s := col.State.Senders[id]
	if s == nil || s.LastSeq != 3 || len(s.Missing) != 1 || s.Missing[0].From != 2 || s.Missing[0].To != 2 {
		t.Fatalf("missing batch not recorded: %+v", s)
	}
	// Batch 1 delivered again (e.g. the sender crashed before removing it).
	os.WriteFile(one, saved, 0o644)
	res, _ := Import(col, in, t0.Add(4*time.Hour), nil)
	evs, _ := col.ReadEvents(time.Time{})
	if res.Records != 0 || len(evs) != 2 {
		t.Errorf("duplicate batch imported again: %d records, %d events", res.Records, len(evs))
	}
}

func TestDeliverNeedsInboxMarker(t *testing.T) {
	ws := system(t, "WS-01", "windows", 1, t0)
	Export(ws, "WS-01", "test", t0)
	// An unmounted share looks like an empty local folder.
	empty := t.TempDir()
	if _, err := Deliver(ws, empty, "WS-01"); !errors.Is(err, ErrNoInbox) {
		t.Fatalf("got %v, want ErrNoInbox", err)
	}
	if Queued(ws) != 1 {
		t.Error("batch should stay queued until the inbox is reachable")
	}
	entries, _ := os.ReadDir(empty)
	if len(entries) != 0 {
		t.Error("wrote into a folder that is not an inbox")
	}
}

func TestRejectsBadFiles(t *testing.T) {
	in := inbox(t)
	os.WriteFile(filepath.Join(in, "WS-01_abc_0000000001.bbx"), []byte("not a batch"), 0o644)
	os.WriteFile(filepath.Join(in, "notes.bbx"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(in, ".WS-01_abc_0000000002.bbx.partial"), []byte("x"), 0o644) // still being copied
	col, _ := store.Open(t.TempDir())
	res, err := Import(col, in, t0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 2 {
		t.Errorf("rejected %v, want the two bad files", res.Rejected)
	}
	if _, err := os.Stat(filepath.Join(in, ".WS-01_abc_0000000002.bbx.partial")); err != nil {
		t.Error("a file still being copied must be left alone")
	}
	if _, err := os.Stat(filepath.Join(in, "rejected", "notes.bbx")); err != nil {
		t.Error("bad file not set aside")
	}
}

func TestInterruptedImportIsUndone(t *testing.T) {
	col, _ := store.Open(t.TempDir())
	col.AppendEvents(t0, []*event.Event{{Time: t0, Host: "A", Summary: "kept"}})
	name := "events-" + t0.Format("2006-01-02") + ".jsonl"
	if err := col.BeginImport([]string{name, "runs-" + t0.Format("2006-01-02") + ".jsonl"}); err != nil {
		t.Fatal(err)
	}
	col.AppendRaw(name, [][]byte{[]byte(`{"host":"B","summary":"half an import"}`)})
	col.AppendRaw("runs-"+t0.Format("2006-01-02")+".jsonl", [][]byte{[]byte(`{"host":"B"}`)})
	// Crash here. Opening to read changes nothing; the next run, which
	// takes the lock, undoes the partial import.
	reader, _ := store.Open(col.Dir)
	if reader.State.Pending == nil {
		t.Fatal("a reader must not undo an import that may still be running")
	}
	again, err := store.Open(col.Dir)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := again.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	evs, _ := again.ReadEvents(time.Time{})
	if len(evs) != 1 || evs[0].Summary != "kept" {
		t.Errorf("after recovery: %d events", len(evs))
	}
	if _, err := os.Stat(filepath.Join(col.Dir, "spool", "runs-"+t0.Format("2006-01-02")+".jsonl")); !os.IsNotExist(err) {
		t.Error("file created by the interrupted import should be removed")
	}
	if again.State.Pending != nil {
		t.Error("pending import not cleared")
	}
}

func TestExportCrashRewritesSameBatch(t *testing.T) {
	ws := system(t, "WS-01", "windows", 2, t0)
	Export(ws, "WS-01", "test", t0)
	// Simulate a crash after the batch was written but before state was
	// saved: reload the old state.
	ws.State.Send.NextSeq = 1
	ws.State.Send.Offsets = map[string]int64{}
	if _, err := Export(ws, "WS-01", "test", t0); err != nil {
		t.Fatal(err)
	}
	if Queued(ws) != 1 || ws.State.Send.NextSeq != 2 {
		t.Errorf("queued %d, next %d: the batch should be rewritten, not duplicated", Queued(ws), ws.State.Send.NextSeq)
	}
}

func TestLargeHistorySplitsIntoBatches(t *testing.T) {
	ws := system(t, "WS-01", "windows", maxBatchLines+10, t0)
	n, err := Export(ws, "WS-01", "test", t0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("made %d batches, want 2", n)
	}
}
