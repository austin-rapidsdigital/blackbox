package report

import (
	_ "embed"
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

// pageData is what the report template is rendered from. Section is set
// while rendering one category's view.
type pageData struct {
	*Report
	Section *Section
}

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
		"logo":      func() template.URL { return template.URL(brand.LogoDataURI()) },
		"brandName": func() string { return brand.Name },
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

// WriteHTML renders the whole report as one self-contained HTML file.
func (r *Report) WriteHTML(w io.Writer) error {
	t, err := template.New("report").Funcs(funcs(r.Location)).Parse(reportTemplate)
	if err != nil {
		return err
	}
	return t.ExecuteTemplate(w, "layout", pageData{Report: r})
}
