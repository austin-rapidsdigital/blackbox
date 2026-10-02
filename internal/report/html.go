package report

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/casea1/blackbox/internal/brand"
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

//go:embed style.css
var styleCSS string

//go:embed app.js
var appJS string

// pageData is what the report template is rendered from. Section is set
// while rendering one category's view.
type pageData struct {
	*Report
	Section *Section
	Pages   []*EventPage
	Meta    template.JS // settings for app.js, as JSON
}

// headData is a page's heading.
type headData struct {
	Crumb, Title, Range string
}

// IsLAN says whether the report covers more than one computer.
func (r *Report) IsLAN() bool { return len(r.Hosts) > 1 || r.Collector }

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
		"logo":  func() template.URL { return template.URL(brand.LogoDataURI()) },
		"css":   func() template.CSS { return template.CSS(styleCSS) },
		"js":    func() template.JS { return template.JS(appJS) },
		"icon":  icon,
		"lower": strings.ToLower,
		"plural": func(n int, unit string) string {
			if n == 1 {
				return unit
			}
			return unit + "s"
		},
		"eventsCrumb": func(p pageData, e *EventPage) string {
			unit := "events"
			if e.Total == 1 {
				unit = "event"
			}
			s := fmt.Sprintf("%s · Events · %s %s", p.Kind(), commas(e.Total), unit)
			if n := len(e.Hosts); n > 1 {
				s += fmt.Sprintf(" on %d systems", n)
			} else if n == 1 {
				s += " on " + e.Hosts[0]
			}
			return s
		},
		// head builds a page heading: the report period and, unless crumb
		// is given, a line describing the report.
		"head": func(p pageData, title, crumb string) headData {
			if crumb == "" {
				crumb = p.Crumb()
			}
			rng := p.PeriodStart().In(loc).Format("2 Jan") + " – " + p.WindowEnd.In(loc).Format("2 Jan 2006")
			return headData{Crumb: crumb, Title: title, Range: rng}
		},
		"brandName": func() string { return brand.Name },
		"fontCSS":   func() template.CSS { return template.CSS(brand.FontCSS()) },
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
		// href links to a view of the report, or to one row in it.
		"href": func(p pageData, view any, anchor string) string {
			if anchor != "" {
				return "#" + anchor
			}
			return "#" + fmt.Sprint(view)
		},
		"withSection": func(p pageData, s *Section) pageData {
			p.Section = s
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

// Crumb is the line above each page title, e.g. "Weekly report · 24
// systems · generated 29 Sep 2026 00:05".
func (r *Report) Crumb() string {
	parts := []string{r.Kind()}
	if r.IsLAN() {
		parts = append(parts, fmt.Sprintf("%d systems", len(r.Hosts)))
	} else if len(r.Hosts) == 1 {
		parts = append(parts, r.Hosts[0])
	}
	parts = append(parts, "generated "+r.Generated.In(r.Location).Format("2 Jan 2006 15:04"))
	return strings.Join(parts, " · ")
}

// Kind is "Weekly report", "Interim report" or "Report".
func (r *Report) Kind() string {
	switch {
	case r.Interim:
		return "Interim report"
	case r.Period != "":
		return strings.ToUpper(r.Period[:1]) + r.Period[1:] + " report"
	}
	return "Report"
}

// WriteHTML renders report.html. The event pages read their events from
// the data files given (see buildData), which go in the data folder.
func (r *Report) WriteHTML(w io.Writer, pages []*EventPage) error {
	t, err := template.New("report").Funcs(funcs(r.Location)).Parse(reportTemplate)
	if err != nil {
		return err
	}
	meta := map[string]any{"pages": pages, "zone": zoneName(r.Generated, r.Location)}
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return t.ExecuteTemplate(w, "layout", pageData{Report: r, Pages: pages, Meta: template.JS(b)})
}

func zoneName(t time.Time, loc *time.Location) string {
	name, _ := t.In(loc).Zone()
	return name
}
