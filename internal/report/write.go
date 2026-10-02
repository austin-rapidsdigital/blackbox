package report

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/casea1/blackbox/internal/archive"
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
	Interim     bool           `json:"interim,omitempty"`
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
	Systems     []SystemStatus `json:"systems,omitempty"`
	Detections  []Detection    `json:"detections,omitempty"`
	Archives    []ArchiveJSON  `json:"log_archives,omitempty"`
	// Metrics are the counts the Trends page charts (see metrics.go).
	Metrics map[string]int `json:"metrics,omitempty"`
}

// ArchiveJSON is one archive of original logs in summary.json.
type ArchiveJSON struct {
	Host   string    `json:"host"`
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	File   string    `json:"file"`
	Bytes  uint64    `json:"bytes"`
	SHA256 string    `json:"sha256"`
}

// Detection is one detection in summary.json.
type Detection struct {
	Severity string    `json:"severity"`
	Time     time.Time `json:"time"`
	Host     string    `json:"host"`
	Title    string    `json:"title"`
	Detail   string    `json:"detail"`
}

// SystemStatus is one computer's line in summary.json.
type SystemStatus struct {
	Name        string    `json:"name"`
	Status      string    `json:"status"` // ok | warn | silent
	LastRun     time.Time `json:"last_collection,omitzero"`
	Events      int       `json:"events"`
	High        int       `json:"high"`
	ChecksFail  int       `json:"audit_settings_failing"`
	Explanation string    `json:"note,omitempty"`
}

func (r *Report) summary() Summary {
	s := Summary{Site: r.Site, WindowStart: r.WindowStart, WindowEnd: r.WindowEnd,
		Generated: r.Generated, Hosts: r.Hosts, Events: len(r.Events), ByCategory: map[string]int{}, Interim: r.Interim,
		LogClears: r.Health.LogClears, Version: r.Version, Source: r.Source, Metrics: r.metrics()}
	if s.WindowStart.IsZero() {
		s.WindowStart = r.FirstEvent
	}
	s.High = len(r.HighRows)
	for _, a := range r.Archives {
		s.Archives = append(s.Archives, ArchiveJSON{Host: a.Host, From: a.From, To: a.To, File: a.Name, Bytes: a.Bytes, SHA256: a.SHA256})
	}
	for _, f := range r.Findings {
		s.Detections = append(s.Detections, Detection{Severity: string(f.Severity), Time: f.Time, Host: f.Host, Title: f.Title, Detail: f.Detail})
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
	if r.ShowSystems() {
		for _, sys := range r.SystemRows {
			st := SystemStatus{Name: sys.Name, Status: sys.Status, LastRun: sys.LastRun, Events: sys.Events, High: sys.High, Explanation: sys.StatusMsg}
			if sys.Checks != nil {
				st.ChecksFail = sys.Checks.Fail
			}
			s.Systems = append(s.Systems, st)
		}
	}
	return s
}

// Write creates dir and writes the report, exports and manifest into it,
// moving the original-log zips (r.Archives) in as well.
func (r *Report) Write(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	var manifest strings.Builder
	r.archiveState = map[string]archiveState{}
	for _, a := range r.Archives {
		dst := filepath.Join(dir, a.Name)
		st := archiveState{}
		if a.Path != "" {
			sum, err := copyIn(a.Path, dst)
			if err != nil {
				return fmt.Errorf("add the original logs %s: %w", a.Name, err)
			}
			st.Verified = a.SHA256 != "" && sum == a.SHA256
		} else if sum, err := archive.FileSHA256(dst); err == nil {
			st.Verified = a.SHA256 != "" && sum == a.SHA256
		}
		st.Contents, _ = archive.Contents(dst)
		r.archiveState[a.Name] = st
	}
	pages, data, err := r.buildData()
	if err != nil {
		return fmt.Errorf("event data: %w", err)
	}
	var html bytes.Buffer
	if err := r.WriteHTML(&html, pages); err != nil {
		return fmt.Errorf("render report: %w", err)
	}
	sum, err := json.MarshalIndent(r.summary(), "", "  ")
	if err != nil {
		return err
	}
	contents := map[string][]byte{
		"report.html":  html.Bytes(),
		"summary.json": append(sum, '\n'),
	}
	if len(data) > 0 {
		if err := os.MkdirAll(filepath.Join(dir, "data"), 0o750); err != nil {
			return err
		}
	}
	for _, f := range data {
		contents["data/"+f.Name] = f.Body
	}

	sums := map[string]string{}
	for _, a := range r.Archives {
		if a.Path != "" {
			sums[a.Name] = a.SHA256
		}
	}
	// Every event as a spreadsheet, zipped: CSV of a busy week is large,
	// and Windows opens a zip with a double-click.
	zsum, err := r.writeEventsZip(filepath.Join(dir, "events.zip"))
	if err != nil {
		return fmt.Errorf("events.zip: %w", err)
	}
	sums["events.zip"] = zsum
	for name, b := range contents {
		if err := store.WriteFileAtomic(filepath.Join(dir, name), b, 0o640); err != nil {
			return err
		}
		h := sha256.Sum256(b)
		sums[name] = hex.EncodeToString(h[:])
	}
	names := make([]string, 0, len(sums))
	for name := range sums {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		// Same format as sha256sum, so `sha256sum -c` also works.
		fmt.Fprintf(&manifest, "%s  %s\n", sums[name], name)
	}
	return store.WriteFileAtomic(filepath.Join(dir, "manifest.sha256"), []byte(manifest.String()), 0o440)
}

// writeEventsZip writes events.zip (events.csv inside), streaming so a
// large report is not held in memory, and returns its SHA-256.
func (r *Report) writeEventsZip(path string) (string, error) {
	tmp := path + ".partial"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	zw := zip.NewWriter(io.MultiWriter(f, h))
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "events.csv", Method: zip.Deflate, Modified: r.Generated})
	if err == nil {
		err = r.writeCSV(w)
	}
	if err == nil {
		err = zw.Close()
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
		// Files are in the report folder, or (event data) in its data folder.
		base := strings.TrimPrefix(name, "data/")
		if strings.ContainsAny(base, `/\`) || base == ".." || base == "." || base == "" {
			problems = append(problems, fmt.Sprintf("%s: unexpected path in manifest", name))
			continue
		}
		got, err := fileSHA256(filepath.Join(dir, name))
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: missing (%v)", name, err))
			continue
		}
		if got != strings.ToLower(want) {
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

// History reads the summaries of the scheduled reports in reportsDir that
// ended before end, oldest first, keeping the last n.
func History(reportsDir string, end time.Time, n int) []Summary {
	matches, _ := filepath.Glob(filepath.Join(reportsDir, "*", "summary.json"))
	var out []Summary
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		var s Summary
		if json.Unmarshal(b, &s) != nil || s.Interim || !s.WindowEnd.Before(end) {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].WindowEnd.Before(out[j].WindowEnd) })
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}

// IndexRow is one report's line on the index page.
type IndexRow struct {
	Week, Dir, Trail, TrailClass, Search string
	Systems, Events, High, Medium        int
	Interim, Incomplete                  bool
}

// indexRow describes one report: its week and whether its audit trail is
// complete (nothing lost, no log cleared, every system reporting).
func indexRow(e IndexEntry, loc *time.Location) IndexRow {
	start := e.WindowStart
	if start.IsZero() {
		start = e.WindowEnd.AddDate(0, 0, -7)
	}
	a, b := start.In(loc), e.WindowEnd.Add(-time.Second).In(loc)
	week := a.Format("2") + " – " + b.Format("2 Jan 2006")
	switch {
	case a.Year() != b.Year():
		week = a.Format("2 Jan 2006") + " – " + b.Format("2 Jan 2006")
	case a.Month() != b.Month():
		week = a.Format("2 Jan") + " – " + b.Format("2 Jan 2006")
	}
	row := IndexRow{Week: week, Dir: e.Dir, Systems: len(e.Hosts), Events: e.Events, Interim: e.Interim}
	for _, d := range e.Detections { // detections by severity, as in the chart
		if d.Severity == "high" {
			row.High++
		} else {
			row.Medium++
		}
	}
	var bad, warn []string
	if e.Lost > 0 {
		bad = append(bad, plural(int(e.Lost), "event")+" lost")
	}
	if e.LogClears > 0 {
		bad = append(bad, plural(e.LogClears, "log")+" cleared")
	}
	if e.AuditOff > 0 {
		bad = append(bad, "auditing was off")
	}
	silent := 0
	for _, s := range e.Systems {
		if s.Status == "silent" {
			silent++
		}
	}
	if silent > 0 {
		bad = append(bad, fmt.Sprintf("%d silent", silent))
	}
	if n := e.Metrics["late_events"]; n > 0 {
		warn = append(warn, fmt.Sprintf("%d late", n))
	}
	switch {
	case len(bad) > 0:
		row.Trail, row.TrailClass, row.Incomplete = strings.Join(append(bad, warn...), " · "), "bad", true
	case len(warn) > 0:
		row.Trail, row.TrailClass = strings.Join(warn, " · "), "warn"
	default:
		row.Trail, row.TrailClass = "Complete", "ok"
	}
	row.Search = week + " " + e.Dir + " " + strings.Join(e.Hosts, " ")
	return row
}

// WriteIndex rebuilds reportsDir/index.html from every report's
// summary.json. schedule describes when reports are made.
func WriteIndex(reportsDir, site, schedule string, loc *time.Location) error {
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
	var rows []IndexRow
	incomplete := 0
	for _, e := range entries {
		row := indexRow(e, loc)
		if row.Incomplete {
			incomplete++
		}
		rows = append(rows, row)
	}
	// Detections per week: the last twelve scheduled reports.
	var weekly []IndexEntry
	for _, e := range entries {
		if !e.Interim && len(weekly) < 12 {
			weekly = append([]IndexEntry{e}, weekly...)
		}
	}
	var chart template.HTML
	if len(weekly) > 1 {
		var labels []string
		hi, md := Series{Name: "High", Color: colBad}, Series{Name: "Medium", Color: colWarn}
		for i, e := range weekly {
			l := weekLabel(e.WindowEnd)
			if i == len(weekly)-1 {
				l = "Latest"
			} else if i%2 == 1 {
				l = ""
			}
			labels = append(labels, l)
			h, m := 0, 0
			for _, d := range e.Detections {
				if d.Severity == "high" {
					h++
				} else {
					m++
				}
			}
			hi.Values, md.Values = append(hi.Values, h), append(md.Values, m)
		}
		chart = stackedBars(labels, []Series{hi, md}, nil, true, 820, 100)
	}
	err = t.Execute(&buf, map[string]any{"Site": site, "Entries": entries, "Rows": rows, "Incomplete": incomplete,
		"Chart": chart, "Weeks": len(weekly), "Schedule": schedule})
	if err != nil {
		return err
	}
	return store.WriteFileAtomic(filepath.Join(reportsDir, "index.html"), buf.Bytes(), 0o640)
}

// fileSHA256 hashes a file in pieces, so large log zips are not read into
// memory.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyIn copies src to dst as a new file, then removes src. It does not
// rename: on Windows a renamed file keeps the permissions of the folder it
// came from (the data folder, Administrators and SYSTEM only), while a new
// file takes the report folder's, like the rest of the report.
func copyIn(src, dst string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	part := dst + ".partial"
	out, err := os.OpenFile(part, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, h), in); err != nil {
		out.Close()
		os.Remove(part)
		return "", err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(part)
		return "", err
	}
	if err := out.Close(); err != nil {
		os.Remove(part)
		return "", err
	}
	if err := os.Rename(part, dst); err != nil {
		return "", err
	}
	in.Close()
	return hex.EncodeToString(h.Sum(nil)), os.Remove(src)
}

// archiveState is what Write found about one original-log zip.
type archiveState struct {
	Verified bool // its SHA-256 matches the one recorded when it was made
	Contents []archive.Info
}
