package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

//go:embed template.html
var reportTemplate string

//go:embed index.html
var indexTemplate string

// pageData is what each page of the report is rendered from.
type pageData struct {
	*Report
	Page    string   // "overview", "health", "people", "review", or a category ID
	Title   string   // browser tab title
	Section *Section // set on category pages
	Full    bool     // single printable file with every page in it
}

// pageFile is the file a page is written to.
func pageFile(page string) string {
	if page == "overview" {
		return "index.html"
	}
	return page + ".html"
}

// FullReportFile is the single printable file containing every page.
const FullReportFile = "full-report.html"

// PeriodStart is the start of the report period (the oldest event on a
// first report).
func (r *Report) PeriodStart() time.Time {
	if r.WindowStart.IsZero() {
		return r.FirstEvent
	}
	return r.WindowStart
}

func funcs(loc *time.Location) template.FuncMap {
	if loc == nil {
		loc = time.Local
	}
	format := func(layout string) func(time.Time) string {
		return func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.In(loc).Format(layout)
		}
	}
	return template.FuncMap{
		"stamp":     format("02 Jan 2006 15:04"),
		"stampSec":  format("02 Jan 2006 15:04:05"),
		"dateLong":  format("Mon 02 Jan 2006"),
		"dateShort": format("02 Jan 2006"),
		"clock":     format("15:04"),
		"zone": func(t time.Time) string {
			name, _ := t.In(loc).Zone()
			return name
		},
		"length": func(a, b time.Time) string {
			if a.IsZero() || b.IsZero() {
				return "—"
			}
			d := b.Sub(a).Round(time.Minute)
			days, hours, mins := int(d.Hours())/24, int(d.Hours())%24, int(d.Minutes())%60
			var parts []string
			if days > 0 {
				parts = append(parts, plural(days, "day"))
			}
			if hours > 0 {
				parts = append(parts, plural(hours, "hour"))
			}
			if mins > 0 && days == 0 {
				parts = append(parts, plural(mins, "minute"))
			}
			if len(parts) == 0 {
				return "under a minute"
			}
			return strings.Join(parts, " ")
		},
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
		"add":  func(a, b int) int { return a + b },
		"bytes": func(b uint64) string {
			if b >= 1<<30 {
				return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
			}
			return fmt.Sprintf("%d MB", b>>20)
		},
		"sevRank":  func(s event.Severity) int { return s.Rank() },
		"catTitle": func(c event.Category) string { return c.Info().Title },
		"mediumTotal": func(gs []AttentionGroup) string {
			n := 0
			for _, g := range gs {
				n += g.Count
			}
			return commas(n)
		},
		// href links to a page, optionally to one row on it. In the full
		// report every page is in the same file, so only the anchor is used.
		"href": func(p pageData, page any, anchor string) string {
			id := fmt.Sprint(page)
			if p.Full {
				if anchor != "" {
					return "#" + anchor
				}
				return "#" + id
			}
			if anchor != "" {
				return pageFile(id) + "#" + anchor
			}
			return pageFile(id)
		},
		// userHref opens a category page filtered to one account.
		"userHref": func(p pageData, cat event.Category, user string) string {
			if p.Full {
				return "#" + string(cat)
			}
			return pageFile(string(cat)) + "#user=" + user
		},
		"withSection": func(p pageData, s *Section) pageData {
			p.Section = s
			p.Page = string(s.Info.ID)
			return p
		},
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// RenderPages renders every page of the report plus the full printable
// file, keyed by file name.
func (r *Report) RenderPages() (map[string][]byte, error) {
	t, err := template.New("report").Funcs(funcs(r.Location)).Parse(reportTemplate)
	if err != nil {
		return nil, err
	}
	pages := []pageData{
		{Report: r, Page: "overview", Title: "Overview"},
		{Report: r, Page: "health", Title: "Audit health"},
		{Report: r, Page: "people", Title: "People"},
	}
	if r.SignatureBlock {
		pages = append(pages, pageData{Report: r, Page: "review", Title: "Review & sign-off"})
	}
	for _, s := range r.Sections {
		pages = append(pages, pageData{Report: r, Page: string(s.Info.ID), Title: s.Info.Title, Section: s})
	}
	pages = append(pages, pageData{Report: r, Page: "overview", Title: "Full report", Full: true})

	out := map[string][]byte{}
	for _, p := range pages {
		var buf bytes.Buffer
		if err := t.ExecuteTemplate(&buf, "layout", p); err != nil {
			return nil, fmt.Errorf("render %s: %w", p.Title, err)
		}
		name := pageFile(p.Page)
		if p.Full {
			name = FullReportFile
		}
		out[name] = buf.Bytes()
	}
	return out, nil
}
