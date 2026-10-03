// How the report turns records into rows: what is left out, what is merged,
// and what one record is re-read as because of another. Build applies them
// in this order:
//
//  1. exclude: exclude_users / exclude_processes leave out routine events only
//     (routine, excludedBy), and Windows' own PowerShell modules are dropped
//     (dropWindowsModules).
//  2. unknownNames: a Linux "wrong password" for a name sshd then calls unknown
//     says "the user name does not exist" (U6).
//  3. mergeAdminLogons: an administrator's 4624 and 4672 (one logon ID) are one
//     logon row with the privileges (U3).
//  4. dedupe: records with the same DedupeKey on one computer within
//     dedupeWindow are one row, keeping the highest Priority; two failed
//     logons of the same kind (recordKind) are two attempts, never merged.
//  5. attributeDevices: a USB device is attributed to whoever mounted it, or
//     to the person at the console.
//  6. shutdownStops: auditd stopping in a reboot or shutdown is routine.
//
// Some merging happens earlier, when the logs are read (package linuxlog):
// the login message and root-shell startup scripts folded into one row
// (startup), the name tried in an unknown-user SSH attempt (triedName), the
// person whose systemctl stopped auditd (stoppedBy), and the sshd,
// sshd-session and sshd-auth programs treated as one (program).

package report

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/winevt"
)

func (r *Report) exclude(in []*event.Event) []*event.Event {
	in = dropWindowsModules(in)
	if len(r.ExcludeUsers) == 0 && len(r.ExcludeProcesses) == 0 {
		return in
	}
	out := in[:0:0]
	for _, e := range in {
		who := r.excludedBy(e)
		if who == "" || !routine(e) {
			out = append(out, e)
			continue
		}
		r.Excluded++
		if r.ExcludedBy == nil {
			r.ExcludedBy, r.ExcludedOn = map[string]int{}, map[string]bool{}
		}
		r.ExcludedBy[who]++
		r.ExcludedOn[e.Host] = true
	}
	return out
}

// excludedText says what the exclusions left out, e.g. "12 routine
// events by svc_backup ×10, scan.exe ×2", or "".
func (r *Report) excludedText() string {
	if r.Excluded == 0 {
		return ""
	}
	by := joinCounts(r.ExcludedBy)
	if len(r.ExcludedBy) == 1 {
		for k := range r.ExcludedBy {
			by = k // one account: its count is the total (U2: not "bbtest ×1")
		}
	}
	return fmt.Sprintf("%s by %s (exclude_users and exclude_processes in the settings)", plural(r.Excluded, "routine event"), by)
}

// routine reports whether an event is everyday activity that an exclusion
// may leave out. Exclusions never hide failed logons (against the
// account), account and group changes (to it), log clears and audit
// changes (by it), or anything of Medium severity or above: excluding an
// account must not hide an attack on it, or by it.
func routine(e *event.Event) bool {
	switch e.Category {
	case event.CatFailedLogon, event.CatAccount, event.CatIntegrity:
		return false
	}
	return e.Severity.Rank() < event.SevMedium.Rank()
}

// excludedBy names the exclude_users or exclude_processes entry an event
// matches, or "". An entry with a domain (CORP\svc_backup) matches that
// account exactly; one without matches the local account of that name,
// not a domain account that happens to share it.
func (r *Report) excludedBy(e *event.Event) string {
	u := strings.ToLower(e.User)
	for _, x := range r.ExcludeUsers {
		lx := strings.ToLower(x)
		if u == lx {
			return x
		}
		if !strings.Contains(lx, `\`) {
			if i := strings.LastIndex(u, `\`); i >= 0 && u[i+1:] == lx && strings.EqualFold(u[:i], shortName(e.Host)) {
				return x
			}
		}
	}
	if e.Process != "" {
		p := strings.ToLower(e.Process)
		base := strings.ToLower(filepath.Base(strings.ReplaceAll(e.Process, `\`, "/")))
		for _, x := range r.ExcludeProcesses {
			if lx := strings.ToLower(x); p == lx || base == lx {
				return x
			}
		}
	}
	return ""
}

// shortName is a host name without its domain.
func shortName(h string) string {
	if i := strings.Index(h, "."); i > 0 {
		return h[:i]
	}
	return h
}

// dedupeWindow is how close in time two events with the same key must be
// to count as one.
func dedupeWindow(key string) time.Duration {
	switch {
	case strings.HasPrefix(key, "authfail|"):
		return 2 * time.Second
	case strings.HasPrefix(key, "lxlogon|"), strings.HasPrefix(key, "lxlogoff|"):
		return 5 * time.Second // one sign-in recorded more than once
	case strings.HasPrefix(key, "4672|"):
		return 24 * time.Hour
	case strings.HasPrefix(key, "rm|"):
		return time.Minute
	case strings.HasPrefix(key, "svc|"), strings.HasPrefix(key, "psblock|"):
		return 10 * time.Minute
	}
	return 5 * time.Minute
}

// dedupe merges events describing the same thing, keeping the most
// informative one (highest Priority). Input must be sorted by time.
func (r *Report) dedupe(in []*event.Event) []*event.Event {
	type slot struct {
		idx   int
		time  time.Time
		kinds map[string]bool // the kinds of record already merged
	}
	last := map[string]*slot{}
	out := make([]*event.Event, 0, len(in))
	for _, e := range in {
		if e.DedupeKey == "" {
			out = append(out, e)
			continue
		}
		k := e.Host + "|" + e.DedupeKey
		kind := recordKind(e)
		s, ok := last[k]
		// A failed logon is often recorded twice (4625 and 4776, or two
		// audit records), so those are merged; but two records of the
		// same kind are two attempts, and password guessing is many
		// attempts in a second.
		if ok && e.Time.Sub(s.time) <= dedupeWindow(e.DedupeKey) && !(strings.HasPrefix(e.DedupeKey, "authfail|") && s.kinds[kind]) {
			r.Duplicates++
			s.kinds[kind] = true
			kept := out[s.idx]
			if e.Priority > kept.Priority {
				out[s.idx], kept, e = e, e, kept
			}
			// One service, recorded under its service name and its
			// display name: show both.
			if strings.HasPrefix(e.DedupeKey, "svc|") && e.Target != "" && !strings.EqualFold(e.Target, kept.Target) {
				kept.AddDetail("Also named", e.Target)
				kept.Summary = strings.Replace(kept.Summary, kept.Target, kept.Target+" ("+e.Target+")", 1)
			}
			continue
		}
		last[k] = &slot{idx: len(out), time: e.Time, kinds: map[string]bool{kind: true}}
		out = append(out, e)
	}
	return out
}

// unknownNames corrects the reason of a Linux password check that failed
// because the account doesn't exist: PAM records it as a wrong password,
// and sshd says a moment later that the name was unknown.
func unknownNames(events []*event.Event) {
	const unknown = "the user name does not exist"
	for i, e := range events {
		if e.OS != "linux" || e.Action != "logon_failed" || !strings.HasSuffix(e.Summary, "— "+unknown+".") {
			continue
		}
		for j := i - 1; j >= 0 && e.Time.Sub(events[j].Time) <= 10*time.Second; j-- {
			x := events[j]
			if x.Host != e.Host || x.Action != "logon_failed" || x.Target != e.Target || x.SourceIP != e.SourceIP ||
				!strings.HasSuffix(x.Summary, "— wrong password.") {
				continue
			}
			x.Summary = strings.TrimSuffix(x.Summary, "wrong password.") + unknown + "."
			for k := range x.Details {
				if x.Details[k].Label == "Reason" {
					x.Details[k].Value = unknown
				}
			}
		}
	}
}

// mergeAdminLogons makes an administrator's logon one row (U3): Windows
// records it as a logon (4624) and as special privileges assigned to it
// (4672), with the same logon ID. The logon row is kept, with the
// privileges, and counts as using administrator rights.
func mergeAdminLogons(events []*event.Event) []*event.Event {
	logons := map[string]*event.Event{}
	for _, e := range events {
		if e.OS == "windows" && e.Action == "logon" && e.EventID == 4624 {
			if id := detail(e, "Logon ID"); id != "" {
				logons[e.Host+"|"+strings.ToLower(id)] = e
			}
		}
	}
	out := events[:0]
	for _, e := range events {
		if e.Action == "admin_logon" && e.EventID == 4672 {
			l := logons[e.Host+"|"+strings.ToLower(detail(e, "Logon ID"))]
			if l != nil && absDur(e.Time.Sub(l.Time)) <= 10*time.Second {
				l.AddDetail("Privileges", detail(e, "Privileges"))
				if !strings.Contains(l.Summary, "administrator") {
					l.Summary = strings.TrimSuffix(l.Summary, ".") + " with administrator privileges."
				}
				if l.Severity.Rank() < event.SevLow.Rank() {
					l.Severity = event.SevLow
				}
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// rebootCmd is a command that restarts or shuts down the system.
var rebootCmd = regexp.MustCompile(`(^|/|\s)(reboot|poweroff|halt|shutdown)(\s|$)|systemctl\s+(reboot|poweroff|halt|kexec)`)

// shutdownStops marks the audit service stopping as part of a restart or
// shutdown (a SYSTEM_SHUTDOWN record, or a reboot command, on the same
// computer within minutes) as routine: it is how every planned restart
// ends, not someone switching auditing off. A stop with neither stays High.
func shutdownStops(events []*event.Event) {
	for i, e := range events {
		if e.Action != "audit_stopped" || e.Severity != event.SevHigh || e.OS == "windows" {
			continue
		}
		near := func(x *event.Event) bool {
			if x.Host != e.Host {
				return false
			}
			return x.Action == "system_stop" || (x.Command != "" && rebootCmd.MatchString(strings.ToLower(x.Command)))
		}
		found := false
		for j := i - 1; j >= 0 && e.Time.Sub(events[j].Time) <= 5*time.Minute && !found; j-- {
			found = near(events[j])
		}
		for j := i + 1; j < len(events) && events[j].Time.Sub(e.Time) <= time.Minute && !found; j++ {
			found = near(events[j])
		}
		if found {
			e.Severity = event.SevInfo
			e.Summary = fmt.Sprintf("The audit service (auditd) stopped as part of a restart or shutdown by %s (normal).", orUnknown(e.User))
		}
	}
}

// recordKind identifies the kind of record an event came from: its log,
// event ID and (Linux audit) record type.
func recordKind(e *event.Event) string {
	return e.Source + "|" + strconv.Itoa(e.EventID) + "|" + e.RecordType
}

// attributeDevices names the person most likely using a removable device:
// device events do not record a user, so use whoever is logged on at the
// console of that host (not remotely: a remote user cannot plug in a
// device). When several people are, the most recent is named and the
// others are listed.
func attributeDevices(events []*event.Event) {
	// Best evidence: the person who mounted the device right after it was
	// connected (recorded by udisks on Linux).
	for i, e := range events {
		if e.Action != "usb_connected" || e.User != "" {
			continue
		}
		for _, m := range events[i+1:] {
			if m.Time.Sub(e.Time) > 2*time.Minute {
				break
			}
			if m.Host == e.Host && m.Action == "removable_mounted" && m.User != "" {
				e.User = m.User
				e.AddDetail("User", m.User+" (opened the device right after it was connected)")
				break
			}
		}
	}
	active := map[string][]string{} // host → console users, oldest first
	remove := func(host, user string) {
		l := active[host]
		for i := len(l) - 1; i >= 0; i-- {
			if l[i] == user {
				active[host] = append(l[:i:i], l[i+1:]...)
				return
			}
		}
	}
	for _, e := range events {
		switch {
		case e.Action == "logon" && consoleLogon(e):
			remove(e.Host, e.User)
			active[e.Host] = append(active[e.Host], e.User)
		case e.Action == "logoff":
			remove(e.Host, e.User)
		case e.Category == event.CatRemovable && e.User == "":
			l := active[e.Host]
			if len(l) == 0 {
				continue
			}
			e.User = l[len(l)-1]
			e.AddDetail("User", e.User+" (logged on at the console at the time; device events do not record a user)")
			if len(l) > 1 {
				e.AddDetail("Also logged on at the console", strings.Join(l[:len(l)-1], ", "))
			}
		}
	}
}

// consoleLogon reports a logon made at the machine itself.
func consoleLogon(e *event.Event) bool {
	switch e.Fields["LogonType"] {
	case "2", "7", "11", "13":
		return true
	}
	for _, d := range e.Details {
		if d.Label == "Logon type" && (d.Value == "Graphical console" || d.Value == "Text console") {
			return true
		}
	}
	return false
}

// dropWindowsModules leaves out script blocks of Windows' own PowerShell
// modules that PowerShell flagged as suspicious, collected before
// Blackbox learned to skip them (see winevt.WindowsModule).
func dropWindowsModules(in []*event.Event) []*event.Event {
	out := in[:0:0]
	for _, e := range in {
		if e.Action == "powershell_suspicious" {
			var text, path string
			for _, d := range e.Details {
				switch d.Label {
				case "Script (excerpt)":
					text = d.Value
				case "Script path":
					path = d.Value
				}
			}
			if winevt.WindowsModule(text, path) {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}
