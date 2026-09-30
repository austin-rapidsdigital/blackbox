package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// WorkingHours is when administrator activity is expected, e.g.
// "Mon-Fri 06:00-18:00". The zero value means not set: nothing is treated
// as outside working hours.
type WorkingHours struct {
	Days       [7]bool // indexed by time.Weekday
	Start, End int     // minutes after midnight; End may be before Start (overnight)
	Text       string
}

// Set reports whether working hours are configured.
func (w WorkingHours) Set() bool { return w.Text != "" }

// Contains reports whether t (in the report's time zone) is within working
// hours. An overnight shift (22:00-06:00) belongs to the day it starts.
func (w WorkingHours) Contains(t time.Time) bool {
	if !w.Set() {
		return true
	}
	m := t.Hour()*60 + t.Minute()
	if w.Start <= w.End {
		return w.Days[t.Weekday()] && m >= w.Start && m < w.End
	}
	if m >= w.Start {
		return w.Days[t.Weekday()]
	}
	return m < w.End && w.Days[(t.Weekday()+6)%7]
}

var dayNames = []string{"sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"}

// dayIndex reads a day name, in full or its first three letters.
func dayIndex(s string) (int, bool) {
	s = strings.ToLower(s)
	for i, d := range dayNames {
		if s == d || s == d[:3] {
			return i, true
		}
	}
	return 0, false
}

func clockMinutes(s string) (int, bool) {
	h, m, ok := strings.Cut(s, ":")
	if !ok {
		return 0, false
	}
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil || hh < 0 || hh > 24 || mm < 0 || mm > 59 || (hh == 24 && mm != 0) {
		return 0, false
	}
	return hh*60 + mm, true
}

// ParseWorkingHours reads "Mon-Fri 06:00-18:00", "Mon,Wed,Fri 07:00-15:30"
// or "Daily 22:00-06:00". An empty value turns the check off.
func ParseWorkingHours(v string) (WorkingHours, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return WorkingHours{}, nil
	}
	bad := fmt.Errorf("working_hours must look like \"Mon-Fri 06:00-18:00\" (got %q)", v)
	days, hours, ok := strings.Cut(v, " ")
	if !ok {
		return WorkingHours{}, bad
	}
	w := WorkingHours{Text: v}
	if strings.EqualFold(days, "daily") {
		for i := range w.Days {
			w.Days[i] = true
		}
	} else {
		for _, part := range strings.Split(days, ",") {
			a, b, isRange := strings.Cut(part, "-")
			from, ok1 := dayIndex(a)
			to := from
			ok2 := true
			if isRange {
				to, ok2 = dayIndex(b)
			}
			if !ok1 || !ok2 {
				return WorkingHours{}, bad
			}
			for i := from; ; i = (i + 1) % 7 {
				w.Days[i] = true
				if i == to {
					break
				}
			}
		}
	}
	s, e, ok := strings.Cut(strings.ReplaceAll(hours, " ", ""), "-")
	start, ok1 := clockMinutes(s)
	end, ok2 := clockMinutes(e)
	if !ok || !ok1 || !ok2 || start == end {
		return WorkingHours{}, bad
	}
	w.Start, w.End = start, end
	return w, nil
}
