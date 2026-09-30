package report

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// Summary is summary.json: a small machine-readable record of the report,
// used to build the index page.
type Summary struct {
	Site        string         `json:"site,omitempty"`
	WindowStart time.Time      `json:"window_start,omitzero"`
	WindowEnd   time.Time      `json:"window_end"`
	Generated   time.Time      `json:"generated"`
	Hosts       []string       `json:"hosts"`
	Events      int            `json:"events"`
	High        int            `json:"high"`
	Medium      int            `json:"medium"`
	ByCategory  map[string]int `json:"by_category"`
	Lost        uint64         `json:"events_lost"`
	LogClears   int            `json:"log_clears"`
	AuditOff    int            `json:"audit_off_periods,omitempty"`
	Version     string         `json:"blackbox_version"`
	Source      string         `json:"source"`
}

func (r *Report) summary() Summary {
	s := Summary{Site: r.Site, WindowStart: r.WindowStart, WindowEnd: r.WindowEnd,
		Generated: r.Generated, Hosts: r.Hosts, Events: len(r.Events), ByCategory: map[string]int{},
		LogClears: r.Health.LogClears, Version: r.Version, Source: r.Source}
	if s.WindowStart.IsZero() {
		s.WindowStart = r.FirstEvent
	}
	s.High = len(r.HighRows)
	for _, f := range r.Findings {
		if f.Severity == event.SevHigh {
			s.High++
		}
	}
	for _, g := range r.Medium {
		s.Medium += g.Count
	}
	for _, sec := range r.Sections {
		s.ByCategory[string(sec.Info.ID)] = sec.Total
	}
	for _, g := range r.Health.Gaps {
		s.Lost += g.Lost
	}
	s.AuditOff = len(r.Health.AuditOff)
	return s
}

// Write creates dir and writes the report, exports and manifest into it.
func (r *Report) Write(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	var html, csvBuf, jsonl bytes.Buffer
	if err := r.WriteHTML(&html); err != nil {
		return fmt.Errorf("render report: %w", err)
	}
	if err := r.writeCSV(&csvBuf); err != nil {
		return err
	}
	enc := json.NewEncoder(&jsonl)
	enc.SetEscapeHTML(false)
	for _, e := range r.Events {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	sum, err := json.MarshalIndent(r.summary(), "", "  ")
	if err != nil {
		return err
	}
	contents := map[string][]byte{
		"report.html":  html.Bytes(),
		"events.csv":   csvBuf.Bytes(),
		"events.jsonl": jsonl.Bytes(),
		"summary.json": append(sum, '\n'),
	}

	names := make([]string, 0, len(contents))
	for name := range contents {
		names = append(names, name)
	}
	sort.Strings(names)
	var manifest strings.Builder
	for _, name := range names {
		if err := store.WriteFileAtomic(filepath.Join(dir, name), contents[name], 0o640); err != nil {
			return err
		}
		h := sha256.Sum256(contents[name])
		// Same format as sha256sum, so `sha256sum -c` also works.
		fmt.Fprintf(&manifest, "%s  %s\n", hex.EncodeToString(h[:]), name)
	}
	return store.WriteFileAtomic(filepath.Join(dir, "manifest.sha256"), []byte(manifest.String()), 0o440)
}

func (r *Report) writeCSV(w io.Writer) error {
	// A UTF-8 byte order mark makes Excel read accented names correctly.
	w.Write([]byte("\xef\xbb\xbf"))
	cw := csv.NewWriter(w)
	cw.Write([]string{"time", "host", "category", "severity", "summary", "user", "target", "source_ip",
		"process", "command", "outcome", "action", "log", "event_id", "record_type", "record_id", "late"})
	for _, e := range r.Events {
		rec, eventID := strconv.FormatUint(e.RecordID, 10), strconv.Itoa(e.EventID)
		if e.RecordID == 0 {
			rec = ""
		}
		if e.EventID == 0 {
			eventID = ""
		}
		cw.Write([]string{e.Time.In(r.Location).Format("2006-01-02 15:04:05"), e.Host, e.Category.Info().Title,
			string(e.Severity), e.Summary, e.User, e.Target, e.SourceIP, e.Process, e.Command, e.Outcome,
			e.Action, e.Source, eventID, e.RecordType, rec, map[bool]string{true: "yes", false: ""}[e.Late]})
	}
	cw.Flush()
	return cw.Error()
}

// DirName returns a folder name for a report ending at end.
func DirName(end time.Time, hosts []string, loc *time.Location) string {
	name := end.In(loc).Format("2006-01-02_1504")
	switch len(hosts) {
	case 0:
	case 1:
		name += "_" + safeName(hosts[0])
	default:
		name += fmt.Sprintf("_%d-systems", len(hosts))
	}
	return name
}

func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, s)
}

// UniqueDir returns parent/name, adding -2, -3… if it already exists.
func UniqueDir(parent, name string) string {
	p := filepath.Join(parent, name)
	for i := 2; ; i++ {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return p
		}
		p = filepath.Join(parent, fmt.Sprintf("%s-%d", name, i))
	}
}

// Verify re-hashes the files listed in dir/manifest.sha256. It returns a
// list of problems (empty if everything matches).
func Verify(dir string) ([]string, error) {
	f, err := os.Open(filepath.Join(dir, "manifest.sha256"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var problems []string
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		want, name, ok := strings.Cut(strings.TrimSpace(sc.Text()), "  ")
		if !ok {
			continue
		}
		n++
		if strings.ContainsAny(name, `/\`) || name == ".." {
			problems = append(problems, fmt.Sprintf("%s: unexpected path in manifest", name))
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: missing (%v)", name, err))
			continue
		}
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != strings.ToLower(want) {
			problems = append(problems, fmt.Sprintf("%s: CHANGED since the report was produced", name))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, fmt.Errorf("manifest.sha256 lists no files")
	}
	return problems, nil
}

// IndexEntry is one row on the index page.
type IndexEntry struct {
	Summary
	Dir string
}

// WriteIndex rebuilds reportsDir/index.html from every report's
// summary.json.
func WriteIndex(reportsDir, site string, loc *time.Location) error {
	matches, err := filepath.Glob(filepath.Join(reportsDir, "*", "summary.json"))
	if err != nil {
		return err
	}
	var entries []IndexEntry
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		var s Summary
		if json.Unmarshal(b, &s) != nil {
			continue
		}
		e := IndexEntry{Summary: s, Dir: filepath.Base(filepath.Dir(m))}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].WindowEnd.After(entries[j].WindowEnd) })
	t, err := template.New("index").Funcs(funcs(loc)).Parse(indexTemplate)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	err = t.Execute(&buf, map[string]any{"Site": site, "Entries": entries})
	if err != nil {
		return err
	}
	return store.WriteFileAtomic(filepath.Join(reportsDir, "index.html"), buf.Bytes(), 0o640)
}
