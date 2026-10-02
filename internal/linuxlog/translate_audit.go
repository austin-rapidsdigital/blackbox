package linuxlog

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// Translator turns Linux log entries into normalized events. One
// Translator should see a host's entries in order, because USB devices are
// assembled from several kernel messages.
type Translator struct {
	Host  string // used when entries do not carry a host name
	Users Users  // uid → name, for logs not in ENRICHED format

	// AuthFromSyslog makes logons, sudo, su and account changes come from
	// auth.log/secure. Only set it when auditd is not available; otherwise
	// the same activity would be reported twice.
	AuthFromSyslog bool

	usb      map[string]*usbDevice // host|port → device being set up
	scsiHost map[string]string     // host|scsi host number → USB port
	recent   []recentCmd           // latest commands, to name groups usermod does not record
	groupPID map[string]string     // host|pid → group just created by useradd
}

type recentCmd struct {
	t    time.Time
	host string
	cmd  string
}

func (t *Translator) remember(tm time.Time, host, cmd string) {
	if cmd == "" {
		return
	}
	t.recent = append(t.recent, recentCmd{tm, host, cmd})
	if len(t.recent) > 32 {
		t.recent = t.recent[len(t.recent)-32:]
	}
}

// groupsFor finds the groups named in a recent usermod, gpasswd, adduser
// or deluser command for acct: shadow-utils on Ubuntu 24.04 records
// "adding user to group" without the group name.
func (t *Translator) groupsFor(tm time.Time, host, acct string) []string {
	for i := len(t.recent) - 1; i >= 0; i-- {
		c := t.recent[i]
		if c.host != host || tm.Sub(c.t) > time.Minute || c.t.After(tm.Add(5*time.Second)) {
			continue
		}
		if g := groupsFromCommand(c.cmd, acct); len(g) > 0 {
			return g
		}
	}
	return nil
}

// groupsFromCommand reads the groups from commands such as
// "usermod -aG sudo,adm bob", "gpasswd -a bob sudo" or "adduser bob sudo".
func groupsFromCommand(cmd, acct string) []string {
	f := strings.Fields(cmd)
	if len(f) < 2 {
		return nil
	}
	hasAcct := false
	for _, w := range f[1:] {
		if w == acct {
			hasAcct = true
		}
	}
	if !hasAcct {
		return nil
	}
	split := func(v string) []string { return strings.Split(v, ",") }
	switch base(f[0]) {
	case "usermod":
		for i, w := range f[1:] {
			switch {
			case strings.HasPrefix(w, "--groups="):
				return split(strings.TrimPrefix(w, "--groups="))
			case w == "--groups" || (strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "--") && strings.HasSuffix(w, "G")):
				if i+2 < len(f) {
					return split(f[i+2])
				}
			}
		}
	case "gpasswd":
		last := f[len(f)-1]
		if last != acct && !strings.HasPrefix(last, "-") {
			return []string{last}
		}
	case "adduser", "deluser", "addgroup", "delgroup":
		var pos []string
		for _, w := range f[1:] {
			if !strings.HasPrefix(w, "-") {
				pos = append(pos, w)
			}
		}
		if len(pos) == 2 && pos[0] == acct {
			return []string{pos[1]}
		}
	}
	return nil
}

// NewTranslator returns a ready Translator.
func NewTranslator(host string, users Users) *Translator {
	if users == nil {
		users = Users{}
	}
	return &Translator{Host: host, Users: users, usb: map[string]*usbDevice{}, scsiHost: map[string]string{},
		groupPID: map[string]string{}}
}

// ---------------------------------------------------------------- auditd

// Audit translates one auditd event, or returns nil if it is routine.
func (t *Translator) Audit(ev *Event) *event.Event {
	t.learnUsers(ev)
	e := t.audit(ev)
	if e == nil {
		return nil
	}
	main := ev.Main()
	e.Time = ev.Time
	e.Host = ev.Node
	if e.Host == "" {
		e.Host = t.Host
	}
	e.OS = "linux"
	e.Source = "auditd"
	e.RecordType = main.Type
	e.RecordID = ev.Serial
	if e.Severity == "" {
		e.Severity = event.SevInfo
	}
	if e.Fields == nil {
		e.Fields = map[string]string{}
		for _, r := range ev.Records {
			for k, v := range r.Fields {
				if _, dup := e.Fields[k]; !dup && v != "" && !strings.HasPrefix(k, "_") {
					e.Fields[k] = v
				}
			}
		}
	}
	e.RedactSecrets()
	return e
}

func (t *Translator) audit(ev *Event) *event.Event {
	if avc := ev.First("AVC"); avc != nil {
		return t.avc(ev, avc)
	}
	r := ev.Main()
	switch r.Type {
	case "USER_LOGIN":
		return t.userLogin(r)
	case "USER_AUTH":
		return t.userAuth(r)
	case "USER_ACCT":
		return t.userAcct(r)
	case "USER_CMD":
		return t.userCmd(r)
	case "USER_START":
		return t.userStart(r)
	case "USER_LOGOUT":
		user := t.acct(r)
		if user == "" {
			return nil
		}
		return &event.Event{Category: event.CatLogon, Action: "logoff", User: user, Outcome: "success",
			Summary: fmt.Sprintf("%s logged off.", user), DedupeKey: "lxlogoff|" + user}
	case "USER_CHAUTHTOK":
		return t.chauthtok(r)
	case "ADD_USER", "DEL_USER", "ADD_GROUP", "DEL_GROUP", "USER_MGMT", "GRP_MGMT", "CHUSER_ID", "CHGRP_ID":
		return t.accountMgmt(r)
	case "CONFIG_CHANGE":
		return t.configChange(r)
	case "DAEMON_START":
		return &event.Event{Category: event.CatIntegrity, Severity: event.SevInfo, Action: "audit_started",
			DedupeKey: "auditd-start", Summary: "The audit service (auditd) started."}
	case "DAEMON_END":
		return t.auditdStopped(r, 2)
	case "SERVICE_STOP":
		if r.Get("unit") == "auditd" {
			return t.auditdStopped(r, 1)
		}
		return nil
	case "DAEMON_ABORT":
		return &event.Event{Category: event.CatIntegrity, Severity: event.SevHigh, Action: "audit_stopped",
			Summary: "The audit service (auditd) stopped because of an error — events after this were not recorded."}
	case "SYSTEM_BOOT":
		return &event.Event{Category: event.CatIntegrity, Action: "system_start", DedupeKey: "boot",
			Summary: "The system started."}
	case "SYSTEM_SHUTDOWN":
		return &event.Event{Category: event.CatIntegrity, Action: "system_stop",
			Summary: "The system shut down."}
	case "ANOM_PROMISCUOUS":
		if r.Get("prom") == "0" || r.Get("prom") == "" {
			return nil
		}
		by := t.actor(r)
		dev := r.Get("dev")
		e := &event.Event{Category: event.CatOther, Severity: event.SevMedium, Action: "promiscuous_mode", User: by,
			Target: dev, Summary: fmt.Sprintf("Network interface %s was put into promiscuous mode (packet capture)", dev)}
		if by != "" {
			e.Summary += " by " + by
		}
		e.Summary += "."
		return e
	case "ANOM_LOGIN_FAILURES", "RESP_ACCT_LOCK", "RESP_ACCT_LOCK_TIMED":
		acct := firstNonEmpty(t.acct(r), r.Fields["SUID"])
		if acct == "" {
			acct = t.Users.Name(r.Get("suid"))
		}
		return &event.Event{Category: event.CatFailedLogon, Severity: event.SevMedium, Action: "account_locked",
			User: acct, Target: acct, Outcome: "failure", DedupeKey: "lock|" + acct,
			Summary: fmt.Sprintf("Account %s was locked after too many failed logon attempts.", orUnknown(acct))}
	case "MAC_STATUS":
		if r.Get("enforcing") == "0" && r.Get("old_enforcing") == "1" {
			by := t.actor(r)
			return &event.Event{Category: event.CatOther, Severity: event.SevHigh, Action: "selinux_permissive", User: by,
				Summary: fmt.Sprintf("SELinux was switched from enforcing to permissive mode by %s — it no longer blocks anything.", orUnknown(by))}
		}
		return nil
	case "SYSCALL":
		return t.syscall(ev, r)
	case "USER_DEVICE":
		return usbguard(r)
	}
	return nil
}

var (
	ruleNameRE = regexp.MustCompile(`name "([^"]*)"`)
	ruleIDRE   = regexp.MustCompile(`\bid ([0-9a-fA-F]{4}:[0-9a-fA-F]{4})`)
)

// usbguard translates a USBGuard decision (it logs USER_DEVICE records with
// target=allow, block or reject). The kernel still logs a blocked device as
// connected, so the report must say it was blocked.
func usbguard(r *Record) *event.Event {
	target := strings.ToLower(r.Get("target"))
	if target != "block" && target != "reject" {
		return nil // allowed devices are reported from the kernel messages
	}
	rule := r.Get("device_rule")
	name, id := "", ""
	if m := ruleNameRE.FindStringSubmatch(rule); m != nil {
		name = m[1]
	}
	if m := ruleIDRE.FindStringSubmatch(rule); m != nil {
		id = m[1]
	}
	what := firstNonEmpty(name, id, "a USB device")
	if name != "" && id != "" {
		what = fmt.Sprintf("%s (ID %s)", name, id)
	}
	e := &event.Event{Category: event.CatRemovable, Severity: event.SevMedium, Action: "usb_blocked", Target: what,
		DedupeKey: "usbblock|" + firstNonEmpty(id, name), Priority: 2,
		Summary: fmt.Sprintf("USBGuard blocked %s; it could not be used.", what)}
	if target == "reject" {
		e.Summary = fmt.Sprintf("USBGuard rejected %s (removed from the system); it could not be used.", what)
	}
	e.AddDetail("Decision", target)
	e.AddDetail("Device rule", rule)
	e.AddDetail("Operation", r.Get("op"))
	return e
}

// learnUsers records uid → name pairs from enriched records, so later
// entries that only carry a number (e.g. udisks "on behalf of uid 1001")
// can show a name.
func (t *Translator) learnUsers(ev *Event) {
	for _, r := range ev.Records {
		for _, p := range [][2]string{{"auid", "AUID"}, {"uid", "UID"}, {"euid", "EUID"}, {"suid", "SUID"}, {"id", "ID"}} {
			num, name := r.Fields[p[0]], r.Fields[p[1]]
			if num == "" || name == "" || name == "unset" || strings.HasPrefix(name, "unknown") {
				continue
			}
			if id, err := strconv.Atoi(num); err == nil && id >= 0 && id < 4294967295 {
				if _, known := t.Users[id]; !known {
					t.Users[id] = name
				}
			}
		}
	}
}

func (t *Translator) hostOf(r *Record) string {
	if r.Node != "" {
		return r.Node
	}
	return t.Host
}

// actor is the person behind an event: the login (audit) user ID, which
// sudo and su do not change.
func (t *Translator) actor(r *Record) string {
	if n := r.Fields["AUID"]; n != "" && n != "unset" {
		return n
	}
	return t.Users.Name(r.Get("auid"))
}

// acct is the account an authentication or account record is about.
func (t *Translator) acct(r *Record) string {
	if a := r.Get("acct"); a != "" {
		return a
	}
	if id := r.Get("id"); id != "" {
		if n := r.Fields["ID"]; n != "" && n != "unknown("+id+")" {
			return n
		}
		return t.Users.Name(id)
	}
	return ""
}

func base(p string) string {
	if p == "" {
		return ""
	}
	return path.Base(p)
}

// session describes how someone logged on.
func session(exe, terminal string) (phrase, label string) {
	b := base(exe)
	switch {
	case b == "sshd" || terminal == "ssh":
		return "via SSH", "SSH"
	case strings.Contains(b, "xrdp"):
		// Remote, not at the machine: must not be treated as the console
		// user when a USB device is plugged in.
		return "via Remote Desktop (RDP)", "Remote Desktop"
	case strings.Contains(b, "gdm") || strings.Contains(b, "lightdm") || strings.Contains(b, "sddm"):
		return "at the graphical console", "Graphical console"
	case b == "login" || strings.HasPrefix(terminal, "tty") || strings.HasPrefix(terminal, "/dev/tty"):
		return "at the text console", "Text console"
	case b == "cockpit-session":
		return "via the Cockpit web console", "Cockpit"
	case b != "":
		return "via " + b, b
	}
	return "", "Unknown"
}

func cleanAddr(a string) string {
	a = strings.TrimPrefix(strings.TrimSpace(a), "::ffff:")
	switch a {
	case "", "?", "::1", "127.0.0.1", "0.0.0.0", "::", "UNKNOWN":
		return ""
	}
	return a
}

func fromAddr(a string) string {
	if a == "" {
		return ""
	}
	return " from " + a
}

func orUnknown(s string) string {
	if s == "" {
		return "an unknown account"
	}
	return s
}

func (t *Translator) userLogin(r *Record) *event.Event {
	acct := t.acct(r)
	exe, term := r.Get("exe"), r.Get("terminal")
	addr := cleanAddr(r.Get("addr"))
	if addr == "" && base(exe) == "sshd" {
		addr = cleanAddr(r.Get("hostname")) // for other programs it is this machine's own name
	}
	how, label := session(exe, term)
	if r.Get("res") == "success" {
		if acct == "" {
			return nil
		}
		e := &event.Event{Category: event.CatLogon, Action: "logon", User: acct, Outcome: "success", SourceIP: addr,
			Interactive: true, Summary: fmt.Sprintf("%s logged on %s%s.", acct, how, fromAddr(addr)), DedupeKey: logonKey(acct, addr)}
		e.AddDetail("Logon type", label)
		e.AddDetail("Source address", addr)
		e.AddDetail("Terminal", term)
		e.AddDetail("Program", exe)
		return e
	}
	reason := "wrong password"
	if base(exe) == "sshd" {
		reason = "wrong password or key"
	}
	if acct == "" || strings.Contains(acct, "invalid") {
		acct, reason = "(unknown user name)", "the user name does not exist"
	}
	return t.failedLogon(acct, how, label, addr, term, exe, reason, 2)
}

func (t *Translator) failedLogon(acct, how, label, addr, term, exe, reason string, prio int) *event.Event {
	e := &event.Event{Category: event.CatFailedLogon, Severity: event.SevLow, Action: "logon_failed",
		User: acct, Target: acct, Outcome: "failure", SourceIP: addr,
		DedupeKey: "authfail|" + base(exe) + "|" + addr + "|" + term + "|" + acct, Priority: prio,
		Summary: fmt.Sprintf("Failed logon for %s %s%s — %s.", acct, how, fromAddr(addr), reason)}
	e.AddDetail("Reason", reason)
	e.AddDetail("Logon type", label)
	e.AddDetail("Source address", addr)
	e.AddDetail("Terminal", term)
	e.AddDetail("Program", exe)
	return e
}

func (t *Translator) userAuth(r *Record) *event.Event {
	if r.Get("res") != "failed" {
		return nil
	}
	actor, acct := t.actor(r), t.acct(r)
	exe, term := r.Get("exe"), r.Get("terminal")
	addr := cleanAddr(r.Get("addr"))
	switch base(exe) {
	case "sudo":
		e := &event.Event{Category: event.CatFailedLogon, Severity: event.SevLow, Action: "logon_failed",
			User: actor, Target: actor, Outcome: "failure",
			Summary: fmt.Sprintf("%s entered a wrong password for sudo.", orUnknown(actor))}
		e.AddDetail("Terminal", term)
		return e
	case "su":
		target := acct
		if target == "" {
			target = "root"
		}
		e := &event.Event{Category: event.CatFailedLogon, Severity: event.SevLow, Action: "logon_failed",
			User: actor, Target: target, Outcome: "failure",
			Summary: fmt.Sprintf("%s failed to switch to %s with su — wrong password.", orUnknown(actor), target)}
		e.AddDetail("Terminal", term)
		return e
	case "unix_chkpwd":
		return nil // helper called by other programs, which log their own failure
	}
	how, label := session(exe, term)
	if acct == "" {
		acct = "(unknown user name)"
	}
	return t.failedLogon(acct, how, label, addr, term, exe, "wrong password", 1)
}

func (t *Translator) userAcct(r *Record) *event.Event {
	if r.Get("res") != "failed" {
		return nil
	}
	acct := t.acct(r)
	how, label := session(r.Get("exe"), r.Get("terminal"))
	return t.failedLogon(orUnknown(acct), how, label, cleanAddr(r.Get("addr")), r.Get("terminal"), r.Get("exe"),
		"the account is expired, locked or not allowed to log on this way", 1)
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

func (t *Translator) userCmd(r *Record) *event.Event {
	actor := t.actor(r)
	if actor == "" {
		actor = t.Users.Name(r.Get("uid"))
	}
	cmd := r.Get("cmd")
	t.remember(r.Time, t.hostOf(r), cmd)
	e := &event.Event{Category: event.CatPrivileged, User: actor, Command: cmd, Process: r.Get("exe"),
		DedupeKey: "cmd|" + actor + "|" + cmdKey(cmd), Priority: 2}
	switch {
	case r.Get("res") == "failed":
		e.Action, e.Severity, e.Outcome = "sudo_denied", event.SevMedium, "failure"
		e.Summary = fmt.Sprintf("%s tried to run a command with sudo but was not permitted: %s", orUnknown(actor), cmd)
	case tampers(cmd):
		e.Action, e.Severity = "audit_tamper_command", event.SevHigh
		e.Summary = fmt.Sprintf("%s used sudo to run a command that can stop or weaken auditing: %s", orUnknown(actor), cmd)
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

func (t *Translator) chauthtok(r *Record) *event.Event {
	// usermod (shadow-utils 4.13+, e.g. Ubuntu 24.04) logs group changes as
	// USER_CHAUTHTOK records; only PAM and passwd operations are passwords.
	op := strings.ToLower(r.Get("op"))
	if !strings.HasPrefix(op, "pam:") && !strings.Contains(op, "password") {
		return t.accountMgmt(r)
	}
	actor, acct := t.actor(r), t.acct(r)
	if acct == "" {
		return nil
	}
	e := &event.Event{Category: event.CatAccount, User: actor, Target: acct}
	switch {
	case r.Get("res") == "failed":
		e.Action, e.Severity, e.Outcome = "password_change", event.SevLow, "failure"
		e.Summary = fmt.Sprintf("A password change for %s failed.", acct)
	case actor == acct:
		e.Action, e.Severity = "password_change", event.SevLow
		e.Summary = fmt.Sprintf("%s changed their own password.", acct)
	case actor == "":
		e.Action, e.Severity = "password_change", event.SevLow
		e.Summary = fmt.Sprintf("The password of %s was changed.", acct)
	default:
		e.Action, e.Severity = "password_reset", event.SevMedium
		e.Summary = fmt.Sprintf("%s changed the password of %s.", actor, acct)
	}
	e.AddDetail("Program", r.Get("exe"))
	return e
}

// privilegedGroups grant administrative rights or access to logs and
// hardware on Linux.
var privilegedGroups = map[string]bool{
	"sudo": true, "wheel": true, "admin": true, "adm": true, "root": true, "lxd": true, "docker": true,
	"disk": true, "shadow": true, "systemd-journal": true, "libvirt": true, "kvm": true,
}

func (t *Translator) accountMgmt(r *Record) *event.Event {
	actor := t.actor(r)
	acct := t.acct(r)
	grp := firstNonEmpty(r.Get("grp"), r.Get("group"))
	op := strings.ToLower(r.Get("op"))
	by := "An administrator"
	if actor != "" {
		by = actor
	}
	e := &event.Event{Category: event.CatAccount, User: actor, Target: acct}
	if r.Get("res") == "failed" {
		e.Outcome = "failure"
	}
	pidKey := t.hostOf(r) + "|" + r.Get("pid")
	switch {
	case r.Type == "ADD_USER":
		if strings.Contains(op, "home") || strings.Contains(op, "mail") {
			return nil // useradd reports each step; the account itself is enough
		}
		// Ubuntu 24.04 logs only the new user's ID; useradd has just
		// created the user's own group with the same name.
		if strings.HasPrefix(acct, "uid ") {
			if g := t.groupPID[pidKey]; g != "" {
				acct, e.Target = g, g
			}
		}
		e.Action, e.Severity = "account_created", event.SevMedium
		e.Summary = fmt.Sprintf("%s created the user account %s.", by, acct)
	case r.Type == "DEL_USER":
		if strings.Contains(op, "home") || strings.Contains(op, "mail") {
			return nil
		}
		e.Action, e.Severity = "account_deleted", event.SevMedium
		e.Summary = fmt.Sprintf("%s deleted the user account %s.", by, acct)
	case r.Type == "ADD_GROUP":
		g := firstNonEmpty(grp, acct)
		if len(t.groupPID) > 256 {
			t.groupPID = map[string]string{}
		}
		t.groupPID[pidKey] = g
		e.Action, e.Severity, e.Target = "group_created", event.SevLow, g
		e.Summary = fmt.Sprintf("%s created the group %s.", by, g)
	case r.Type == "DEL_GROUP":
		g := firstNonEmpty(grp, acct)
		e.Action, e.Severity, e.Target = "group_deleted", event.SevMedium, g
		e.Summary = fmt.Sprintf("%s deleted the group %s.", by, g)
	case grp == "" && strings.Contains(op, "group") && (strings.Contains(op, "add") || strings.Contains(op, "remov") || strings.Contains(op, "delet")):
		// Ubuntu 24.04: "adding user to group", with the group left out.
		groups := t.groupsFor(r.Time, t.hostOf(r), acct)
		adding := strings.Contains(op, "add")
		g := strings.Join(groups, ", ")
		if g == "" {
			g = "a group (the log does not say which)"
		} else if len(groups) > 1 {
			g = "the groups " + g
		} else {
			g = "the group " + g
		}
		if adding {
			e.Action, e.Severity = "group_member_added", event.SevMedium
			e.Summary = fmt.Sprintf("%s added %s to %s.", by, acct, g)
			for _, x := range groups {
				if privilegedGroups[x] {
					e.Severity = event.SevHigh
					e.Summary = fmt.Sprintf("%s added %s to the privileged %s.", by, acct, strings.TrimPrefix(g, "the "))
					e.AddDetail("Why it matters", "Members of this group have administrative rights or can read protected logs.")
					break
				}
			}
			e.DedupeKey = "grp|add|" + acct + "|" + strings.Join(groups, ",")
		} else {
			e.Action, e.Severity = "group_member_removed", event.SevMedium
			e.Summary = fmt.Sprintf("%s removed %s from %s.", by, acct, g)
			e.DedupeKey = "grp|del|" + acct + "|" + strings.Join(groups, ",")
		}
	case grp != "" && (strings.Contains(op, "add") || strings.Contains(op, "adding")):
		e.Action, e.Severity = "group_member_added", event.SevMedium
		e.Summary = fmt.Sprintf("%s added %s to the group %s.", by, acct, grp)
		if privilegedGroups[grp] {
			e.Severity = event.SevHigh
			e.Summary = fmt.Sprintf("%s added %s to the privileged group %s.", by, acct, grp)
			e.AddDetail("Why it matters", "Members of this group have administrative rights or can read protected logs.")
		}
		e.DedupeKey = "grp|add|" + acct + "|" + grp // usermod also reports the shadow group
	case grp != "" && (strings.Contains(op, "remov") || strings.Contains(op, "delet")):
		e.Action, e.Severity = "group_member_removed", event.SevMedium
		e.Summary = fmt.Sprintf("%s removed %s from the group %s.", by, acct, grp)
		e.DedupeKey = "grp|del|" + acct + "|" + grp
	case strings.Contains(op, "unlock"):
		e.Action, e.Severity = "account_unlocked", event.SevLow
		e.Summary = fmt.Sprintf("%s unlocked the user account %s.", by, acct)
	case strings.Contains(op, "lock"):
		e.Action, e.Severity = "account_disabled", event.SevMedium
		e.Summary = fmt.Sprintf("%s locked the user account %s.", by, acct)
	default:
		if acct == "" {
			return nil
		}
		e.Action, e.Severity = "account_changed", event.SevLow
		e.Summary = fmt.Sprintf("%s changed the user account %s (%s).", by, acct, strings.TrimSpace(op))
		e.DedupeKey = "acctchg|" + acct
	}
	if e.DedupeKey == "" {
		e.DedupeKey = "acct|" + e.Action + "|" + e.Target
	}
	if e.Outcome == "failure" {
		e.Summary = strings.TrimSuffix(e.Summary, ".") + " — the attempt failed."
	}
	e.AddDetail("Operation", r.Get("op"))
	e.AddDetail("Program", r.Get("exe"))
	return e
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func (t *Translator) configChange(r *Record) *event.Event {
	actor := t.actor(r)
	if v, ok := r.Fields["audit_enabled"]; ok {
		switch v {
		case "0":
			return &event.Event{Category: event.CatIntegrity, Severity: event.SevHigh, Action: "audit_disabled", User: actor,
				Summary: fmt.Sprintf("Kernel auditing was turned OFF by %s — nothing is recorded until it is turned back on.", orUnknown(actor))}
		case "2":
			if actor == "" {
				return nil // rules locked at boot, as the STIG requires
			}
			return &event.Event{Category: event.CatIntegrity, Severity: event.SevInfo, Action: "audit_locked", User: actor,
				Summary: fmt.Sprintf("%s locked the audit rules (they cannot be changed until reboot).", actor)}
		case "1":
			if actor == "" || r.Fields["old"] == "1" {
				return nil
			}
			return &event.Event{Category: event.CatIntegrity, Severity: event.SevLow, Action: "audit_enabled", User: actor,
				Summary: fmt.Sprintf("%s turned kernel auditing on.", actor)}
		}
	}
	if actor == "" {
		return nil // rules loaded at boot
	}
	op := r.Get("op")
	key := r.Get("key")
	rule := ""
	if key != "" {
		rule = " (" + key + ")"
	}
	e := &event.Event{Category: event.CatIntegrity, User: actor, Target: key}
	switch op {
	case "remove_rule":
		e.Action, e.Severity = "audit_rule_removed", event.SevHigh
		e.Summary = fmt.Sprintf("%s removed an audit rule%s — activity it covered is no longer recorded.", actor, rule)
		e.DedupeKey = "auditrule|remove"
	case "add_rule":
		e.Action, e.Severity = "audit_rule_added", event.SevMedium
		e.Summary = fmt.Sprintf("%s added an audit rule%s.", actor, rule)
		e.DedupeKey = "auditrule|add"
	default:
		e.Action, e.Severity = "audit_config_changed", event.SevMedium
		e.Summary = fmt.Sprintf("%s changed the audit configuration (%s).", actor, orUnknownOp(op))
	}
	return e
}

func orUnknownOp(op string) string {
	if op == "" {
		return "setting not recorded"
	}
	return op
}

func (t *Translator) auditdStopped(r *Record, prio int) *event.Event {
	actor := t.actor(r)
	e := &event.Event{Category: event.CatIntegrity, Action: "audit_stopped", User: actor,
		DedupeKey: "auditd-stop", Priority: prio}
	if actor != "" {
		e.Severity = event.SevHigh
		e.Summary = fmt.Sprintf("The audit service (auditd) was stopped by %s — events are not recorded while it is stopped.", actor)
	} else {
		e.Severity = event.SevLow
		e.Summary = "The audit service (auditd) stopped (normal during a system shutdown)."
	}
	return e
}

var avcRE = regexp.MustCompile(`avc:\s+(denied|granted)\s+\{\s*([^}]*?)\s*\}`)

func (t *Translator) avc(ev *Event, avc *Record) *event.Event {
	comm := firstNonEmpty(avc.Get("comm"), ev.Main().Get("comm"))
	name := firstNonEmpty(avc.Get("name"), avc.Get("path"))
	if aa := avc.Get("apparmor"); aa != "" {
		if aa != "DENIED" {
			return nil
		}
		op := avc.Get("operation")
		profile := avc.Get("profile")
		e := &event.Event{Category: event.CatOther, Severity: event.SevLow, Action: "mac_denied", Process: comm, Target: name,
			DedupeKey: "mac|" + profile + "|" + op + "|" + name,
			Summary:   fmt.Sprintf("AppArmor blocked %s from %s on %s.", orUnknownProg(comm), op, orUnknownProg(name))}
		e.AddDetail("Profile", profile)
		e.AddDetail("Requested", avc.Get("requested_mask"))
		return e
	}
	m := avcRE.FindStringSubmatch(avc.Fields["_raw"])
	if m == nil || m[1] != "denied" {
		return nil
	}
	perms := m[2]
	class := avc.Get("tclass")
	e := &event.Event{Category: event.CatOther, Severity: event.SevLow, Action: "mac_denied", Process: comm, Target: name,
		DedupeKey: "mac|" + comm + "|" + perms + "|" + name}
	if avc.Get("permissive") == "1" {
		e.Summary = fmt.Sprintf("SELinux would have blocked %s from %s on %s %s (permissive mode, so it was allowed).", orUnknownProg(comm), perms, class, orUnknownProg(name))
	} else {
		e.Summary = fmt.Sprintf("SELinux blocked %s from %s on %s %s.", orUnknownProg(comm), perms, class, orUnknownProg(name))
	}
	e.AddDetail("Process context", avc.Get("scontext"))
	e.AddDetail("Target context", avc.Get("tcontext"))
	return e
}

func orUnknownProg(s string) string {
	if s == "" {
		return "an unknown program"
	}
	return s
}

// ---------------------------------------------------------------- SYSCALL events

// accountTools legitimately write /etc/passwd, /etc/shadow and /etc/group;
// their changes are reported from ADD_USER/USER_MGMT records instead.
var accountTools = map[string]bool{
	"useradd": true, "usermod": true, "userdel": true, "groupadd": true, "groupmod": true, "groupdel": true,
	"gpasswd": true, "passwd": true, "chpasswd": true, "chage": true, "chfn": true, "chsh": true,
	"newusers": true, "adduser": true, "deluser": true, "addgroup": true, "delgroup": true,
	"pwconv": true, "grpconv": true, "systemd-sysusers": true, "systemd-sysuser": true, "update-passwd": true,
}

// setuidHelpers are privileged programs reported another way (sudo and su
// have their own records) or that only run as part of normal logons.
var setuidHelpers = map[string]bool{
	"sudo": true, "su": true, "sudoedit": true, "pkexec": true, "unix_chkpwd": true, "ssh-keysign": true,
	"dbus-daemon-launch-helper": true, "polkit-agent-helper-1": true, "Xorg.wrap": true, "fusermount3": true,
	"fusermount": true, "gnome-keyring-daemon": true, "chrome-sandbox": true,
	// Started at every desktop logon; the STIG audits it as a privileged program.
	"ssh-agent": true,
}

var identityFiles = map[string]bool{
	"/etc/passwd": true, "/etc/shadow": true, "/etc/group": true, "/etc/gshadow": true, "/etc/security/opasswd": true,
}

// syscallName uses the enriched name, or common x86_64 numbers.
// destroysFile reports whether a system call deletes, renames or empties
// the file it names (opening with O_TRUNC is how "> file" empties one).
func destroysFile(sc string, r *Record) bool {
	switch sc {
	case "unlink", "unlinkat", "rename", "renameat", "renameat2", "truncate", "ftruncate", "rmdir", "creat":
		return true
	case "open":
		return truncates(r.Get("a1"))
	case "openat", "openat2":
		return truncates(r.Get("a2"))
	}
	return false
}

// truncates reports whether open flags (hex, as auditd records them)
// include O_TRUNC.
func truncates(hexFlags string) bool {
	f, err := strconv.ParseUint(hexFlags, 16, 64)
	return err == nil && f&0o1000 != 0
}

func syscallName(r *Record) string {
	if n := r.Fields["SYSCALL"]; n != "" {
		return n
	}
	switch r.Get("syscall") {
	case "59":
		return "execve"
	case "322":
		return "execveat"
	case "175":
		return "init_module"
	case "313":
		return "finit_module"
	case "176":
		return "delete_module"
	case "165":
		return "mount"
	case "166":
		return "umount2"
	case "227":
		return "clock_settime"
	case "164":
		return "settimeofday"
	case "159":
		return "adjtimex"
	case "305":
		return "clock_adjtime"
	// File changes (x86_64 numbers; ENRICHED logs give the names).
	case "2":
		return "open"
	case "257":
		return "openat"
	case "85":
		return "creat"
	case "76":
		return "truncate"
	case "77":
		return "ftruncate"
	case "82":
		return "rename"
	case "264":
		return "renameat"
	case "316":
		return "renameat2"
	case "87":
		return "unlink"
	case "263":
		return "unlinkat"
	case "84":
		return "rmdir"
	case "169":
		return "reboot"
	}
	return r.Get("syscall")
}

func commandLine(ev *Event) string {
	if p := ev.First("PROCTITLE"); p != nil && p.Get("proctitle") != "" {
		return p.Get("proctitle")
	}
	if x := ev.First("EXECVE"); x != nil {
		var args []string
		for i := 0; ; i++ {
			v, ok := x.Fields[fmt.Sprintf("a%d", i)]
			if !ok {
				break
			}
			args = append(args, v)
		}
		return strings.Join(args, " ")
	}
	return ""
}

func (t *Translator) syscall(ev *Event, r *Record) *event.Event {
	actor := t.actor(r)
	if r.Get("success") == "no" {
		return nil // an attempt that did nothing
	}
	// Changes to sudo rules, the account database and log files matter
	// whoever makes them; everything else is reported only for people.
	who := actor
	if who == "" {
		who = "A system process (no logged-in user)"
	}
	sc := syscallName(r)
	exe := r.Get("exe")
	prog := base(exe)
	cmd := commandLine(ev)
	if sc == "execve" || sc == "execveat" {
		t.remember(r.Time, t.hostOf(r), cmd)
	}
	shown := firstNonEmpty(cmd, exe)
	using := ""
	if prog != "" {
		using = " (using " + prog + ")"
	}
	var paths []string
	for _, p := range ev.All("PATH") {
		if n := p.Get("name"); n != "" && p.Get("nametype") != "PARENT" {
			if !strings.HasPrefix(n, "/") {
				if cwd := ev.First("CWD"); cwd != nil && cwd.Get("cwd") != "" {
					n = path.Join(cwd.Get("cwd"), n)
				}
			}
			paths = append(paths, n)
		}
	}

	// Changes to who can use sudo.
	for _, p := range paths {
		if p == "/etc/sudoers" || strings.HasPrefix(p, "/etc/sudoers.d/") {
			e := &event.Event{Category: event.CatPrivileged, Severity: event.SevHigh, Action: "sudoers_changed",
				User: actor, Target: p, Process: exe, DedupeKey: "sudoers|" + p,
				Summary: fmt.Sprintf("%s changed the sudo rules: %s%s.", who, p, using)}
			e.AddDetail("File", p)
			e.AddDetail("Command", cmd)
			return e
		}
	}
	// The account database edited directly, not with the account tools.
	for _, p := range paths {
		if identityFiles[p] && !accountTools[prog] && !accountTools[r.Get("comm")] {
			e := &event.Event{Category: event.CatAccount, Severity: event.SevHigh, Action: "account_db_edited",
				User: actor, Target: p, Process: exe, DedupeKey: "iddb|" + p,
				Summary: fmt.Sprintf("%s edited %s directly%s instead of with the standard account tools.", who, p, using)}
			e.AddDetail("File", p)
			e.AddDetail("Command", cmd)
			return e
		}
	}
	// Log files deleted, renamed or emptied by a person. Ordinary writes are
	// not tampering: sudo appends to /var/log/sudo.log and logins update
	// wtmp and lastlog, and the STIG audit rules watch those files.
	for _, p := range paths {
		if actor != "" && strings.HasPrefix(p, "/var/log/") && destroysFile(sc, r) {
			e := &event.Event{Category: event.CatIntegrity, Severity: event.SevHigh, Action: "log_tampered",
				User: actor, Target: p, Process: exe, DedupeKey: "logfile|" + p,
				Summary: fmt.Sprintf("%s deleted, renamed or emptied the log file %s%s.", actor, p, using)}
			e.AddDetail("System call", sc)
			e.AddDetail("Command", cmd)
			return e
		}
	}

	if actor == "" {
		return nil // routine system activity
	}
	switch sc {
	case "init_module", "finit_module":
		return &event.Event{Category: event.CatOther, Severity: event.SevMedium, Action: "module_loaded", User: actor,
			Process: exe, Command: cmd, Summary: fmt.Sprintf("%s loaded a kernel module: %s", actor, shown)}
	case "delete_module":
		return &event.Event{Category: event.CatOther, Severity: event.SevMedium, Action: "module_unloaded", User: actor,
			Process: exe, Command: cmd, Summary: fmt.Sprintf("%s unloaded a kernel module: %s", actor, shown)}
	case "clock_settime", "settimeofday", "adjtimex", "clock_adjtime", "stime":
		return &event.Event{Category: event.CatIntegrity, Severity: event.SevMedium, Action: "time_changed", User: actor,
			Process: exe, Command: cmd, DedupeKey: "time|" + actor,
			Summary: fmt.Sprintf("%s changed the system time%s: %s", actor, using, shown)}
	case "mount":
		e := &event.Event{Category: event.CatOther, Severity: event.SevLow, Action: "filesystem_mounted", User: actor,
			Process: exe, Command: cmd, Summary: fmt.Sprintf("%s mounted a filesystem: %s", actor, shown)}
		for _, w := range strings.Fields(cmd) {
			if strings.HasPrefix(w, "/media/") || strings.HasPrefix(w, "/run/media/") || strings.HasPrefix(w, "/mnt") {
				e.Category, e.Severity, e.Action = event.CatRemovable, event.SevMedium, "removable_mounted"
				e.Summary = fmt.Sprintf("%s mounted a disk: %s", actor, shown)
			}
		}
		return e
	case "execve", "execveat":
		if setuidHelpers[prog] {
			return nil
		}
		uid, euid := r.Get("uid"), r.Get("euid")
		key := r.Get("key")
		if key == "" && uid == euid {
			return nil
		}
		e := &event.Event{Category: event.CatPrivileged, Severity: event.SevLow, User: actor, Process: exe, Command: cmd}
		if uid == "0" && euid == "0" {
			// A person's command running as root: from a root shell (sudo -i,
			// su) or started by sudo (then the sudo record is kept instead).
			e.Action = "root_command"
			e.DedupeKey, e.Priority = "cmd|"+actor+"|"+cmdKey(cmd), 1
			e.Summary = fmt.Sprintf("%s ran as root: %s", actor, shown)
		} else {
			e.Action = "privileged_program"
			e.Summary = fmt.Sprintf("%s ran the privileged program %s", actor, prog)
			if cmd != "" && cmd != prog {
				e.Summary += ": " + cmd
			} else {
				e.Summary += "."
			}
		}
		if tampers(cmd) {
			e.Action, e.Severity = "audit_tamper_command", event.SevHigh
			e.Summary = fmt.Sprintf("%s ran a command that can stop or weaken auditing: %s", actor, shown)
		}
		e.AddDetail("Program", exe)
		e.AddDetail("Command", cmd)
		e.AddDetail("Runs as", t.Users.Name(euid))
		e.AddDetail("Audit rule", key)
		return e
	}
	return nil
}
