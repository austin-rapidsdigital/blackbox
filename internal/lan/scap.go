package lan

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/scap"
	"github.com/casea1/blackbox/internal/store"
)

// SCAP scan results travel from a sender to its collector next to its
// batches, compressed, each file once (docs/design.md 13a).
const scapExt, scapPrefix = ".xml.gz", "scap_"

// QueueScap puts scan result files not sent before into the outbox.
func QueueScap(st *store.Store, files []string, now time.Time) (int, error) {
	if st.State.ScapSent == nil {
		st.State.ScapSent = map[string]time.Time{}
	}
	n := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return n, err
		}
		sum := sha256.Sum256(b)
		id := hex.EncodeToString(sum[:])
		if _, sent := st.State.ScapSent[id]; sent {
			continue
		}
		if strings.HasSuffix(strings.ToLower(f), ".gz") {
			if z, err := gzip.NewReader(bytes.NewReader(b)); err == nil {
				var plain bytes.Buffer
				if _, err := plain.ReadFrom(z); err == nil {
					b = plain.Bytes()
				}
			}
		}
		var gz bytes.Buffer
		w := gzip.NewWriter(&gz)
		w.Write(b)
		w.Close()
		dir := OutboxDir(st)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return n, err
		}
		if err := store.WriteFileAtomic(filepath.Join(dir, scapPrefix+id[:16]+scapExt), gz.Bytes(), 0o640); err != nil {
			return n, err
		}
		st.State.ScapSent[id] = now
		n++
	}
	return n, nil
}

// QueuedScap is the number of scan results waiting in the outbox.
func QueuedScap(st *store.Store) int {
	list, _ := listOutbox(st, scapExt)
	return len(list)
}

// DeliverScap copies waiting scan results into the collector's inbox.
func DeliverScap(st *store.Store, inbox string) (int, error) {
	if !IsInbox(inbox) {
		return 0, fmt.Errorf("%w: %s", ErrNoInbox, inbox)
	}
	list, err := listOutbox(st, scapExt)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, name := range list {
		src := filepath.Join(OutboxDir(st), name)
		if err := copyInto(src, inbox, scapPrefix+st.State.Send.ID+"_"+strings.TrimPrefix(name, scapPrefix)); err != nil {
			return sent, fmt.Errorf("copy SCAP result %s to %s: %w", name, inbox, err)
		}
		if err := os.Remove(src); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

// importScap checks a delivered scan result and files it under the
// computer it is for.
func importScap(st *store.Store, inbox, name, scapDir string) error {
	id, _, _ := strings.Cut(strings.TrimPrefix(name, scapPrefix), "_")
	if st.State.Send != nil && id == st.State.Send.ID {
		return fmt.Errorf("it was sent by this computer (a system cannot send to itself)")
	}
	path := filepath.Join(inbox, name)
	res, err := scap.ReadFile(path)
	if err != nil {
		return fmt.Errorf("not a SCAP result: %w", err)
	}
	host := store.SystemKey(res[0].Host)
	if host == "" {
		host = "UNKNOWN"
	}
	dir := filepath.Join(scapDir, safeName(host))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := store.WriteFileAtomic(filepath.Join(dir, name), b, 0o640); err != nil {
		return err
	}
	return os.Remove(path)
}
