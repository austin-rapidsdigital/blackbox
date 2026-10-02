package gui

import (
	"fmt"
	"image"
	"image/color"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/app"
	"github.com/casea1/blackbox/internal/brand"
	"github.com/casea1/blackbox/internal/install"
)

// trayState is the status icon's colour (SETUP-SPEC.md, "What it shows").
type trayState int

const (
	stateOK      trayState = iota // green: collecting on schedule
	stateLook                     // amber: something to look at
	stateStopped                  // red: collection stopped or failed
	stateUnknown                  // grey: status can't be read
)

// trayView is what the icon, its tooltip and its menu show.
type trayView struct {
	State   trayState
	Tip     string   // tooltip
	Status  string   // first menu line
	Items   []string // one line per thing to look at
	Report  string   // latest report.html ("" if none)
	Reports string   // reports folder
}

// overdue is how long without a run before collection counts as stopped:
// twice the interval plus 15 minutes.
func overdue(every time.Duration) time.Duration { return 2*every + 15*time.Minute }

func clock(t time.Time) string { return t.Local().Format("15:04") }

// when is a short time: "14:05" today, "Tue 14:05" this week, else "29 Sep".
func when(t, now time.Time) string {
	t, now = t.Local(), now.Local()
	switch {
	case t.YearDay() == now.YearDay() && t.Year() == now.Year():
		return t.Format("15:04")
	case now.Sub(t) < 6*24*time.Hour && t.Before(now):
		return t.Format("Mon 15:04")
	case t.After(now) && t.Sub(now) < 6*24*time.Hour:
		return t.Format("Mon 15:04")
	}
	return t.Format("2 Jan")
}

// classify turns the state into the icon and menu.
func classify(h app.Health, err error, now time.Time) trayView {
	v := trayView{Reports: h.ReportsDir}
	if h.Latest != nil {
		v.Report = filepath.Join(h.Latest.Dir, "report.html")
	}
	if err != nil {
		v.State, v.Status = stateUnknown, "Status can't be read: "+err.Error()
		v.Tip = "Blackbox: status can't be read"
		return v
	}
	every := strings.TrimPrefix(install.EveryText(h.Every), "every ")
	switch {
	case h.LastCollect.IsZero() && h.LastRun.Time.IsZero():
		v.Status = "Waiting for the first collection"
		v.Tip = "Blackbox: waiting for the first collection"
	case h.LastRun.Error != "" && !h.LastRun.Time.Before(h.LastCollect):
		v.State = stateStopped
		v.Status = "The last run failed (" + when(h.LastRun.Time, now) + "): " + h.LastRun.Error
		v.Tip = "Blackbox: the last run failed"
	case now.Sub(h.LastCollect) > overdue(h.Every):
		v.State = stateStopped
		v.Status = "Collection has stopped: last run " + when(h.LastCollect, now)
		v.Tip = "Blackbox: collection has stopped"
	default:
		v.Status = "Collecting every " + every + " · last " + clock(h.LastCollect)
		if h.ReportsDir != "" {
			if h.NextReport.IsZero() {
				v.Status += " · report at the next run"
			} else {
				v.Status += " · next report " + when(h.NextReport, now)
			}
		}
		v.Tip = "Blackbox: collecting · last " + clock(h.LastCollect)
	}

	// Things to look at, by system name.
	var hosts []string
	for host := range h.AuditGaps {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		v.Items = append(v.Items, fmt.Sprintf("Audit settings: %s to fix on %s", plural(h.AuditGaps[host], "setting"), host))
	}
	for _, host := range h.AVOld {
		v.Items = append(v.Items, "Defender intelligence out of date on "+host)
	}
	var quiet []string
	for host := range h.Quiet {
		quiet = append(quiet, host)
	}
	sort.Strings(quiet)
	for _, host := range quiet {
		v.Items = append(v.Items, fmt.Sprintf("%s has not sent since %s", host, when(h.Quiet[host], now)))
	}
	if h.Rejected > 0 {
		v.Items = append(v.Items, fmt.Sprintf("%s set aside in the inbox", plural(h.Rejected, "file")))
	}
	if len(v.Items) > 0 && v.State == stateOK {
		v.State = stateLook
		v.Tip += " · " + plural(len(v.Items), "thing") + " to look at"
	}
	if len(v.Tip) > 127 {
		v.Tip = v.Tip[:124] + "..."
	}
	return v
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// trayMemory is what has already been notified, kept per person so each
// notification is shown once.
type trayMemory struct {
	Seen    bool              `json:"seen"`    // the first look has been taken
	Report  string            `json:"report"`  // latest scheduled report notified
	Stopped string            `json:"stopped"` // outage notified (its last run)
	Quiet   map[string]string `json:"quiet"`   // host → last run notified
	Gaps    map[string]bool   `json:"gaps"`    // hosts whose settings didn't match
	Version string            `json:"version"` // version last running
}

// notice is one notification.
type notice struct {
	Title, Text string
	Warn        bool
	Open        string // report to open when it is clicked
}

// notices works out what to notify, and what to remember. On the first
// look nothing is notified: only what changes after it.
func notices(m trayMemory, h app.Health, v trayView, version string, now time.Time) ([]notice, trayMemory) {
	var out []notice
	next := trayMemory{Seen: true, Report: m.Report, Stopped: m.Stopped, Quiet: map[string]string{}, Gaps: map[string]bool{}, Version: version}
	first := !m.Seen

	if m.Version != "" && m.Version != version {
		out = append(out, notice{Title: "Blackbox updated", Text: "Blackbox updated to " + version + "."})
	}

	if l := h.Latest; l != nil && !l.Interim {
		if l.Dir != m.Report && !first {
			kind := "Scheduled"
			if h.ReportEvery != "" {
				kind = strings.ToUpper(h.ReportEvery[:1]) + h.ReportEvery[1:]
			}
			d := len(l.Detections)
			text := kind + " report ready: " + plural(d, "detection")
			high := 0
			for _, x := range l.Detections {
				if x.Severity == "high" {
					high++
				}
			}
			if high > 0 {
				text += fmt.Sprintf(", %d high", high)
			}
			out = append(out, notice{Title: "Blackbox", Text: text + ".", Open: filepath.Join(l.Dir, "report.html")})
		}
		next.Report = l.Dir
	}

	if v.State == stateStopped {
		key := h.LastCollect.String() + "|" + h.LastRun.Error
		if key != m.Stopped && !first {
			out = append(out, notice{Title: "Blackbox", Text: v.Status, Warn: true})
		}
		next.Stopped = key
	} else {
		next.Stopped = ""
	}

	for host, last := range h.Quiet {
		key := last.String()
		if m.Quiet[host] != key && !first {
			out = append(out, notice{Title: "Blackbox", Text: fmt.Sprintf("%s has not sent its events since %s.", host, when(last, now)), Warn: true})
		}
		next.Quiet[host] = key
	}

	var hosts []string
	for host := range h.AuditGaps {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		if !m.Gaps[host] && !first {
			out = append(out, notice{Title: "Blackbox", Warn: true,
				Text: fmt.Sprintf("Audit settings on %s no longer match the STIG: %s to fix.", host, plural(h.AuditGaps[host], "setting"))})
		}
		next.Gaps[host] = true
	}
	return out, next
}

// Icon colours.
var (
	dotOK      = color.NRGBA{0x1E, 0x9E, 0x4A, 0xFF}
	dotLook    = color.NRGBA{0xE0, 0x8A, 0x00, 0xFF}
	dotStopped = color.NRGBA{0xD0, 0x2B, 0x2B, 0xFF}
)

// trayImage is the logo with a coloured dot in the corner, or the logo in
// grey when the status can't be read.
func trayImage(size int, s trayState) *image.NRGBA {
	img := brand.Logo(size)
	if s == stateUnknown {
		for i := 0; i < len(img.Pix); i += 4 {
			g := uint8((uint16(img.Pix[i])*30 + uint16(img.Pix[i+1])*59 + uint16(img.Pix[i+2])*11) / 100)
			img.Pix[i], img.Pix[i+1], img.Pix[i+2] = g, g, g
		}
		return img
	}
	dot := map[trayState]color.NRGBA{stateOK: dotOK, stateLook: dotLook, stateStopped: dotStopped}[s]
	r := float64(size) * 0.25 // dot radius
	ring := r + float64(size)*0.06
	cx, cy := float64(size)-r-1, float64(size)-r-1
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx, dy := float64(x)+0.5-cx, float64(y)+0.5-cy
			d2 := dx*dx + dy*dy
			switch {
			case d2 <= r*r:
				img.SetNRGBA(x, y, dot)
			case d2 <= ring*ring:
				img.SetNRGBA(x, y, color.NRGBA{0xFF, 0xFF, 0xFF, 0xFF})
			}
		}
	}
	return img
}
