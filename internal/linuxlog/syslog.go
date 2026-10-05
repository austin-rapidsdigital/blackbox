package linuxlog

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Line is one parsed syslog-style line (auth.log, secure, syslog,
// messages, kern.log, or journalctl output).
type Line struct {
	Time time.Time
	Host string
	Prog string // program name, e.g. sshd, sudo, kernel, udisksd
	PID  int
	Msg  string
}

var (
	// "Sep 28 06:02:01 host prog[123]: msg" (Ubuntu 22.04, Alma 8)
	traditionalRE = regexp.MustCompile(`^([A-Z][a-z]{2}) +(\d{1,2}) (\d\d:\d\d:\d\d) (\S+) (.*)$`)
	// "2026-09-28T06:02:01.123456-04:00 host prog[123]: msg" (Ubuntu 24.04,
	// journalctl -o short-iso / short-iso-precise)
	isoRE = regexp.MustCompile(`^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)) (\S+) (.*)$`)
	// "prog[123]: msg" or "prog: msg"
	tagRE = regexp.MustCompile(`^([^\s\[:]+)(?:\[(\d+)\])?: ?(.*)$`)
	// kernel uptime prefix "[ 1234.567890] "
	uptimeRE = regexp.MustCompile(`^\[\s*\d+\.\d+\]\s*`)
)

// LineParser parses syslog lines. Traditional timestamps have no year or
// zone, so the parser assumes Loc and the year of Ref (or the year before,
// for lines that would otherwise be in the future, e.g. December lines read
// in January).
type LineParser struct {
	Loc *time.Location
	Ref time.Time
}

// Parse returns the parsed line, or false if it is not syslog format.
func (p *LineParser) Parse(s string) (Line, bool) {
	s = strings.TrimRight(s, "\r") // a log copied through Windows has CRLF line ends
	var l Line
	var rest string
	if m := isoRE.FindStringSubmatch(s); m != nil {
		ts := m[1]
		// journalctl writes -0400; RFC 3339 needs -04:00.
		if n := len(ts); n > 5 && (ts[n-5] == '+' || ts[n-5] == '-') && !strings.Contains(ts[n-6:], ":") {
			ts = ts[:n-2] + ":" + ts[n-2:]
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return l, false
		}
		l.Time, l.Host, rest = t, m[2], m[3]
	} else if m := traditionalRE.FindStringSubmatch(s); m != nil {
		loc := p.Loc
		if loc == nil {
			loc = time.Local
		}
		ref := p.Ref
		if ref.IsZero() {
			ref = time.Now()
		}
		t, err := time.ParseInLocation("2006 Jan 2 15:04:05", strconv.Itoa(ref.Year())+" "+m[1]+" "+m[2]+" "+m[3], loc)
		if err != nil {
			return l, false
		}
		if t.After(ref.Add(24 * time.Hour)) {
			t = t.AddDate(-1, 0, 0)
		}
		l.Time, l.Host, rest = t, m[4], m[5]
	} else {
		return l, false
	}
	m := tagRE.FindStringSubmatch(rest)
	if m == nil {
		l.Msg = rest
		return l, true
	}
	l.Prog = m[1]
	l.PID, _ = strconv.Atoi(m[2])
	l.Msg = m[3]
	if l.Prog == "kernel" {
		l.Msg = uptimeRE.ReplaceAllString(l.Msg, "")
	}
	return l, true
}
