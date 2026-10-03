// Commands: sudo (USER_CMD), su (USER_START), audit-tampering and
// Blackbox-changing commands, and the logon's own startup scripts
// (login message, root login shell profile) that are folded away.

package linuxlog

import (
	"fmt"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// startup is a logon's own scripts running as root in a session: the
// login message (pam_motd runs /etc/update-motd.d) or a root login
// shell's profile (sudo -i, su -).
type startup struct {
	t    time.Time
	motd bool
}

// profileCommands are what /etc/profile, /etc/profile.d, /etc/bash.bashrc
// and the default .bashrc and .profile run when a login shell starts.
var profileCommands = map[string]bool{
	"locale-check": true, "id": true, "lesspipe": true, "dircolors": true, "tty": true, "mesg": true, "groups": true,
	"basename": true, "dirname": true, "uname": true, "locale": true, "hostname": true, "debuginfod-find": true,
	"byobu-launch": true, "byobu-launcher": true, "whoami": true,
}

// startup reports whether a root command belongs to a logon's own scripts
// rather than to the person. skip is true when it does; e is then the one
// line kept for them (the scripts starting), or nil for each command they
// run.
func (t *Translator) startup(r *Record, actor, cmd string) (e *event.Event, skip bool) {
	if actor == "" || r.Get("euid") != "0" {
		return nil, false
	}
	if t.starting == nil {
		t.starting = map[string]startup{}
	}
	k := t.hostOf(r) + "|" + r.Get("ses")
	f := strings.Fields(cmd)
	switch {
	case len(f) > 0 && base(f[0]) == "run-parts" && strings.Contains(cmd, "/etc/update-motd.d"):
		t.starting[k] = startup{r.Time, true}
		return &event.Event{Category: event.CatPrivileged, Severity: event.SevInfo, Action: "login_scripts", User: actor,
			Process: r.Get("exe"), Command: cmd, DedupeKey: "motd|" + actor,
			Summary: fmt.Sprintf("The login message scripts (/etc/update-motd.d) ran as root when %s logged on; the commands they ran are not listed.", actor)}, true
	case len(f) > 0 && strings.HasPrefix(f[0], "-") && shells[strings.TrimPrefix(base(f[0]), "-")]:
		t.starting[k] = startup{r.Time, false}
		return &event.Event{Category: event.CatPrivileged, Severity: event.SevInfo, Action: "login_scripts", User: actor,
			Process: r.Get("exe"), Command: cmd, DedupeKey: "rootlogin|" + actor,
			Summary: fmt.Sprintf("%s started a root login shell (%s); the commands its startup scripts ran are not listed.", actor, f[0])}, true
	}
	s, ok := t.starting[k]
	if !ok {
		return nil, false
	}
	switch {
	case s.motd && r.Time.Sub(s.t) <= 30*time.Second:
		// Everything run as root before the session itself starts is the
		// login message.
		return nil, true
	case !s.motd && r.Time.Sub(s.t) <= 3*time.Second && len(f) > 0:
		p := base(f[0])
		if profileCommands[p] || strings.Contains(cmd, "/etc/profile.d/") ||
			(p == "cat" && strings.Contains(cmd, "/etc/debuginfod/")) {
			return nil, true
		}
		return nil, false
	}
	delete(t.starting, k)
	return nil, false
}

// endStartup marks a session's own scripts finished: the session has
// started, or the person ran sudo or su.
func (t *Translator) endStartup(host, ses string) {
	if t.starting != nil {
		delete(t.starting, host+"|"+ses)
	}
}

type recentCmd struct {
	t    time.Time
	host string
	cmd  string
	who  string
}

func (t *Translator) remember(tm time.Time, host, cmd, who string) {
	if cmd == "" {
		return
	}
	t.recent = append(t.recent, recentCmd{tm, host, cmd, who})
	if len(t.recent) > 32 {
		t.recent = t.recent[len(t.recent)-32:]
	}
}

// auditTamper are command fragments that stop, weaken or erase auditing
// and logging on Linux.
var auditTamper = []string{
	"systemctl stop auditd", "systemctl disable auditd", "systemctl mask auditd", "service auditd stop",
	"auditctl -d", "auditctl -e 0", "auditctl -e0",
	"systemctl stop rsyslog", "systemctl disable rsyslog", "systemctl stop systemd-journald",
	"systemctl stop apparmor", "systemctl disable apparmor", "aa-teardown", "aa-disable", "aa-complain",
	"setenforce 0", "setenforce permissive", "journalctl --vacuum", "journalctl --rotate",
	"history -c", "unset histfile",
}

func tampers(cmd string) bool {
	lc := strings.Join(strings.Fields(strings.ToLower(cmd)), " ")
	for _, f := range auditTamper {
		if strings.Contains(lc, f) {
			return true
		}
	}
	if strings.Contains(lc, "/var/log") {
		for _, v := range []string{"rm ", "shred", "truncate", "> /var/log", ">/var/log", "mv ", "unlink"} {
			if strings.Contains(lc, v) {
				return true
			}
		}
	}
	return false
}

var shells = map[string]bool{"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true, "fish": true, "-bash": true}

func firstWord(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return ""
	}
	return base(f[0])
}

// cmdKey identifies a command for merging sudo's record with the program
// it ran: the program's name without its folder, and every argument, so
// "systemctl status cron" and "systemctl stop rsyslog" stay apart.
func cmdKey(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return ""
	}
	f[0] = base(f[0])
	return strings.Join(f, " ")
}

// blackboxChange marks a command that changes Blackbox itself (A5, U9):
// a setting, its schedule, or removing it.
func blackboxChange(e *event.Event, cmd, who string) bool {
	action, sev, what, ok := event.BlackboxChange(cmd)
	if !ok {
		return false
	}
	e.Action, e.Severity, e.Category = action, sev, event.CatIntegrity
	e.Summary = fmt.Sprintf("%s %s: %s", who, what, cmd)
	return true
}

func (t *Translator) userCmd(r *Record) *event.Event {
	actor := t.actor(r)
	if actor == "" {
		actor = t.Users.Name(r.Get("uid"))
	}
	cmd := r.Get("cmd")
	t.remember(r.Time, t.hostOf(r), cmd, actor)
	e := &event.Event{Category: event.CatPrivileged, User: actor, Command: cmd, Process: r.Get("exe"),
		DedupeKey: "cmd|" + actor + "|" + cmdKey(cmd), Priority: 2}
	switch {
	case r.Get("res") == "failed":
		e.Action, e.Severity, e.Outcome = "sudo_denied", event.SevMedium, "failure"
		e.Summary = fmt.Sprintf("%s tried to run a command with sudo but was not permitted: %s", orUnknown(actor), cmd)
	case tampers(cmd):
		e.Action, e.Severity = "audit_tamper_command", event.SevHigh
		e.Summary = fmt.Sprintf("%s used sudo to run a command that can stop or weaken auditing: %s", orUnknown(actor), cmd)
	case blackboxChange(e, cmd, orUnknown(actor)):
	case shells[firstWord(cmd)] || strings.TrimSpace(cmd) == "-i" || strings.TrimSpace(cmd) == "-s":
		e.Action, e.Severity = "root_shell", event.SevLow
		e.Summary = fmt.Sprintf("%s opened a root shell with sudo (commands run in it are listed as \"ran as root\").", orUnknown(actor))
	default:
		e.Action, e.Severity = "sudo_command", event.SevLow
		e.Summary = fmt.Sprintf("%s ran with sudo: %s", orUnknown(actor), cmd)
	}
	e.AddDetail("Command", cmd)
	e.AddDetail("Working directory", r.Get("cwd"))
	e.AddDetail("Terminal", r.Get("terminal"))
	return e
}

func (t *Translator) userStart(r *Record) *event.Event {
	t.endStartup(t.hostOf(r), r.Get("ses"))
	if r.Get("res") != "success" {
		return nil
	}
	actor, acct := t.actor(r), t.acct(r)
	switch base(r.Get("exe")) {
	case "su":
		if acct == "" || acct == actor {
			return nil
		}
		e := &event.Event{Category: event.CatPrivileged, Severity: event.SevLow, Action: "switch_user", User: actor, Target: acct,
			Summary: fmt.Sprintf("%s switched to %s with su.", orUnknown(actor), acct)}
		if acct == "root" {
			e.Summary = fmt.Sprintf("%s switched to root with su (a root shell: commands run in it are listed as \"ran as root\").", orUnknown(actor))
		}
		e.AddDetail("Terminal", r.Get("terminal"))
		return e
	case "pkexec":
		return &event.Event{Category: event.CatPrivileged, Severity: event.SevLow, Action: "pkexec", User: actor, Target: acct,
			Summary: fmt.Sprintf("%s ran a program as %s with pkexec.", orUnknown(actor), orUnknown(acct))}
	}
	return nil
}
