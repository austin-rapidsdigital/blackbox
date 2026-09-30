package lan

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/store"
)

// OutboxDir is where batches wait until they reach the collector.
func OutboxDir(st *store.Store) string { return filepath.Join(st.Dir, "outbox") }

// Export turns everything in the spool that has not been sent yet into
// numbered batches in the outbox. It returns the number of batches made.
func Export(st *store.Store, host, version string, now time.Time) (int, error) {
	if st.State.Send == nil {
		st.State.Send = &store.SendState{ID: store.NewID(), NextSeq: 1}
	}
	s := st.State.Send
	if s.Offsets == nil {
		s.Offsets = map[string]int64{}
	}
	if err := os.MkdirAll(OutboxDir(st), 0o750); err != nil {
		return 0, err
	}
	files, err := st.SpoolFiles()
	if err != nil {
		return 0, err
	}
	made := 0
	b := &Batch{}
	advance := map[string]int64{} // offsets reached by the batch being built
	flush := func() error {
		if b.Records() == 0 {
			return nil
		}
		b.Header = Header{Sender: host, SenderID: s.ID, Seq: s.NextSeq, Created: now, Version: version, OS: runtime.GOOS}
		data, err := b.Bytes()
		if err != nil {
			return err
		}
		// Written to the outbox before the offsets move: a crash in between
		// makes the same batch again next time, never loses it.
		if err := store.WriteFileAtomic(filepath.Join(OutboxDir(st), outboxName(s.NextSeq)), data, 0o640); err != nil {
			return err
		}
		for name, off := range advance {
			s.Offsets[name] = off
		}
		s.NextSeq++
		if err := st.Save(); err != nil {
			return err
		}
		made++
		b, advance = &Batch{}, map[string]int64{}
		return nil
	}
	for _, f := range files {
		off := s.Offsets[f.Name]
		if off > f.Size {
			off = 0 // the file was replaced; send it again from the start
		}
		for off < f.Size {
			room := maxBatchLines - b.Records()
			lines, next, err := store.ReadLines(f.Path, off, room)
			if err != nil {
				return made, err
			}
			if next == off {
				break // only an incomplete final line remains
			}
			switch f.Kind {
			case "events":
				b.Events = append(b.Events, lines...)
			case "runs":
				b.Runs = append(b.Runs, lines...)
			case "checks":
				b.Checks = append(b.Checks, lines...)
			}
			off = next
			advance[f.Name] = next
			if b.Records() >= maxBatchLines {
				if err := flush(); err != nil {
					return made, err
				}
			}
		}
	}
	return made, flush()
}

func outboxName(seq uint64) string { return fmt.Sprintf("%010d%s", seq, batchExt) }

// Queued returns the number of batches waiting in the outbox.
func Queued(st *store.Store) int {
	list, _ := outbox(st)
	return len(list)
}

// outbox lists waiting batches, oldest first.
func outbox(st *store.Store) ([]string, error) { return listOutbox(st, batchExt) }

// listOutbox lists the outbox files with the extension, in name order.
func listOutbox(st *store.Store, ext string) ([]string, error) {
	entries, err := os.ReadDir(OutboxDir(st))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ext) && !strings.HasPrefix(e.Name(), ".") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// ErrNoInbox means the collector's folder is not reachable: not mounted,
// not connected, or not a Blackbox inbox.
var ErrNoInbox = errors.New("collector inbox not available")

// Deliver copies waiting batches, oldest first, into the collector's inbox
// and removes each from the outbox once it is safely there. It stops at the
// first failure; what is left is retried at the next run.
func Deliver(st *store.Store, inbox, host string) (int, error) {
	if !IsInbox(inbox) {
		return 0, fmt.Errorf("%w: %s (is the shared folder connected or mounted? on the collector, the folder must be set as its inbox)", ErrNoInbox, inbox)
	}
	list, err := outbox(st)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, name := range list {
		seq, err := strconv.ParseUint(strings.TrimSuffix(name, batchExt), 10, 64)
		if err != nil {
			continue
		}
		src := filepath.Join(OutboxDir(st), name)
		final := InboxName(host, st.State.Send.ID, seq)
		if err := copyInto(src, inbox, final); err != nil {
			return sent, fmt.Errorf("copy batch %d to %s: %w", seq, inbox, err)
		}
		if err := os.Remove(src); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

// Archives are zips of the original logs (see package archive), queued in
// the outbox next to the batches and delivered after them.
const archiveExt, archivePrefix = ".zip", "archive_"

// QueuedArchives returns the number of log archives waiting in the outbox.
func QueuedArchives(st *store.Store) int {
	list, _ := listOutbox(st, archiveExt)
	return len(list)
}

// DeliverArchives copies waiting log archives into the collector's inbox,
// named with this sender's ID, and removes each from the outbox once it is
// safely there.
func DeliverArchives(st *store.Store, inbox string) (int, error) {
	if !IsInbox(inbox) {
		return 0, fmt.Errorf("%w: %s", ErrNoInbox, inbox)
	}
	list, err := listOutbox(st, archiveExt)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, name := range list {
		src := filepath.Join(OutboxDir(st), name)
		if err := copyInto(src, inbox, archivePrefix+st.State.Send.ID+"_"+name); err != nil {
			return sent, fmt.Errorf("copy log archive %s to %s: %w", name, inbox, err)
		}
		if err := os.Remove(src); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

// InboxName is a batch's file name in the inbox: sender, stream ID and
// sequence number, so batches sort in order and never collide.
func InboxName(host, id string, seq uint64) string {
	return fmt.Sprintf("%s_%s_%010d%s", safeName(host), id, seq, batchExt)
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

func safeName(s string) string {
	s = unsafeChars.ReplaceAllString(s, "-")
	if s == "" {
		return "unknown"
	}
	return s
}

// copyInto copies src into dir as name: written under a temporary name,
// flushed to disk, then renamed, so the collector never sees half a file.
func copyInto(src, dir, name string) error {
	final := filepath.Join(dir, name)
	if _, err := os.Stat(final); err == nil {
		return nil // already delivered (the outbox copy was not removed last time)
	}
	tmp := filepath.Join(dir, "."+name+".partial")
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		if _, serr := os.Stat(final); serr == nil {
			os.Remove(tmp)
			return nil
		}
		os.Remove(tmp)
		return err
	}
	return nil
}
