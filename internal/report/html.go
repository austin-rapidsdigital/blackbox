package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

//go:embed template.html
var reportTemplate string

//go:embed index.html
var indexTemplate string

func funcs(loc *time.Location) template.FuncMap {
	if loc == nil {
		loc = time.Local
	}
	return template.FuncMap{
		"stamp": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.In(loc).Format("2006-01-02 15:04")
		},
		"stampFull": func(t time.Time) string { return t.In(loc).Format("2006-01-02 15:04:05 MST") },
		"commas": func(v any) string {
			switch n := v.(type) {
			case int:
				return commas(n)
			case uint64:
				return commas(n)
			}
			return fmt.Sprint(v)
		},
		"join": strings.Join,
		"dur":  roughDuration,
		"pct":  func(p float64) string { return fmt.Sprintf("%.1f%%", p) },
		"bytes": func(b uint64) string {
			if b >= 1<<30 {
				return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
			}
			return fmt.Sprintf("%d MB", b>>20)
		},
		"sevRank":  func(s event.Severity) int { return s.Rank() },
		"catTitle": func(c event.Category) string { return c.Info().Title },
		// css passes a validated color through html/template's CSS filter.
		"css": func(s string) template.CSS {
			if len(s) == 7 && s[0] == '#' && strings.Trim(s[1:], "0123456789abcdefABCDEF") == "" {
				return template.CSS(s)
			}
			return template.CSS("#444444")
		},
		"period": func(r *Report) string {
			start := r.WindowStart
			if start.IsZero() {
				start = r.FirstEvent
			}
			if start.IsZero() {
				return "—"
			}
			return start.In(loc).Format("2006-01-02 15:04") + " to " + r.WindowEnd.In(loc).Format("2006-01-02 15:04")
		},
		"zone": func(r *Report) string {
			name, off := r.Generated.In(loc).Zone()
			return fmt.Sprintf("%s (UTC%+03d:%02d)", name, off/3600, abs(off%3600)/60)
		},
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// WriteHTML renders the report.
func (r *Report) WriteHTML(w io.Writer) error {
	t, err := template.New("report").Funcs(funcs(r.Location)).Parse(reportTemplate)
	if err != nil {
		return err
	}
	return t.Execute(w, r)
}
