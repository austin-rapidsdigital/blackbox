package winevt

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/casea1/blackbox/internal/event"
)

// Translator turns raw Windows events into normalized events.
type Translator struct {
	// ResolveSID looks up an account name for a SID. Optional; on a live
	// Windows system it asks the OS.
	ResolveSID func(sid string) string

	// MapDevicePath turns \Device\HarddiskVolumeN\… into a drive-letter
	// path. Optional; set on a live Windows system.
	MapDevicePath func(path string) string

	sidNames map[string]string    // learned from events seen so far
	logons   map[string]logonInfo // recent 4624s by host|logon ID
}

type logonInfo struct{ logonType, ip string }

// NewTranslator returns a ready Translator.
func NewTranslator() *Translator {
	return &Translator{sidNames: map[string]string{}, logons: map[string]logonInfo{}}
}

// Channels are the logs Blackbox reads on a live Windows system.
var Channels = []string{
	"Security",
	"System",
	"Microsoft-Windows-Partition/Diagnostic",
	"Microsoft-Windows-Kernel-PnP/Configuration",
	"Microsoft-Windows-DriverFrameworks-UserMode/Operational",
	"Microsoft-Windows-Windows Defender/Operational",
	"Microsoft-Windows-PowerShell/Operational",
}

// Translate returns the normalized event for r, or nil if r is not
// security-relevant (or is routine system noise).
func (t *Translator) Translate(r *Raw) *event.Event {
	t.learnSIDs(r)
	e := t.translate(r)
	if e == nil {
		return nil
	}
	e.Time = r.Time
	e.Host = shortHost(r.Computer)
	e.OS = "windows"
	e.Source = r.Channel
	e.EventID = r.EventID
	e.RecordID = r.RecordID
	if e.Severity == "" {
		e.Severity = event.SevInfo
	}
	if e.Fields == nil {
		e.Fields = r.Data
	}
	e.RedactSecrets()
	return e
}

func (t *Translator) translate(r *Raw) *event.Event {
	switch {
	case r.Channel == "Security" || r.Provider == "Microsoft-Windows-Security-Auditing":
		return t.security(r)
	case r.Channel == "System":
		return t.system(r)
	case r.Channel == "Microsoft-Windows-Partition/Diagnostic":
		return t.partition(r)
	case r.Channel == "Microsoft-Windows-Kernel-PnP/Configuration":
		return t.kernelPnP(r)
	case r.Channel == "Microsoft-Windows-DriverFrameworks-UserMode/Operational":
		return t.driverFrameworks(r)
	case r.Channel == "Microsoft-Windows-Windows Defender/Operational":
		return t.defender(r)
	case r.Channel == "Microsoft-Windows-PowerShell/Operational":
		return t.powerShell(r)
	}
	return nil
}

// ---------------------------------------------------------------- Security

func (t *Translator) security(r *Raw) *event.Event {
	switch r.EventID {
	case 4624:
		return t.logonSuccess(r)
	case 4625:
		return t.logonFailure(r)
	case 4647:
		return t.logoff(r)
	case 4634:
		return t.sessionEnded(r)
	case 4778, 4779:
		return t.rdpSession(r)
	case 4648:
		return t.explicitCreds(r)
	case 4672:
		return t.specialPrivileges(r)
	case 4688:
		return t.processCreated(r)
	case 4697:
		return t.serviceInstalled(r, r.Get("ServiceName"), r.Get("ServiceFileName"), r.Get("ServiceAccount"), t.subject(r))
	case 4698, 4699, 4700, 4701, 4702:
		return t.scheduledTask(r)
	case 4719:
		return t.auditPolicyChanged(r)
	case 1100:
		return &event.Event{Category: event.CatIntegrity, Severity: event.SevLow, Action: "eventlog_shutdown",
			Summary: "The event logging service shut down (normal during a system shutdown)."}
	case 1102:
		u := t.subject(r)
		return &event.Event{Category: event.CatIntegrity, Severity: event.SevHigh, Action: "log_cleared",
			User: u, Target: "Security", Summary: fmt.Sprintf("The Security log was cleared by %s.", orUnknown(u))}
	case 1104:
		return &event.Event{Category: event.CatIntegrity, Severity: event.SevHigh, Action: "log_full",
			Summary: "The Security log is full — new security events are not being recorded."}
	case 1105:
		e := &event.Event{Category: event.CatIntegrity, Severity: event.SevInfo, Action: "log_archived",
			Summary: "The Security log was automatically archived."}
		e.AddDetail("Archive file", r.Get("BackupPath"))
		return e
	case 1108:
		return &event.Event{Category: event.CatIntegrity, Severity: event.SevMedium, Action: "eventlog_error",
			Summary: "The event logging service reported an error while processing events."}
	case 4608:
		return &event.Event{Category: event.CatIntegrity, Action: "system_start", DedupeKey: "boot", Priority: 1,
			Summary: "Windows started up."}
	case 4616:
		return t.timeChanged(r)
	case 4720, 4722, 4723, 4724, 4725, 4726, 4738, 4767, 4781:
		return t.accountChange(r)
	case 4727, 4730, 4731, 4734, 4754, 4758:
		return t.groupLifecycle(r)
	case 4728, 4729, 4732, 4733, 4756, 4757:
		return t.groupMembership(r)
	case 4740:
		acct := r.Get("TargetUserName")
		e := &event.Event{Category: event.CatFailedLogon, Severity: event.SevMedium, Action: "account_locked",
			User: acct, Target: acct, Outcome: "failure",
			Summary: fmt.Sprintf("Account %s was locked out after too many failed logon attempts.", acct)}
		e.AddDetail("Attempts came from", r.Get("TargetDomainName"))
		return e
	case 4771:
		return t.kerberosFailure(r)
	case 4776:
		return t.ntlmValidation(r)
	case 4656, 4663:
		return t.removableAccess(r)
	case 6416:
		return t.pnpDevice(r)
	}
	return nil
}

func (t *Translator) logonSuccess(r *Raw) *event.Event {
	lt := r.Get("LogonType")
	user := t.account(r, "TargetUserSid", "TargetDomainName", "TargetUserName")
	if lt == "0" || lt == "5" || t.isServiceAccount(r.Get("TargetUserSid"), r.Get("TargetUserName")) {
		return nil
	}
	e := &event.Event{Category: event.CatLogon, Action: "logon", User: user, Outcome: "success",
		SourceIP: cleanIP(r.Get("IpAddress")), Interactive: interactiveLogon(lt) || lt == "7" || lt == "13"}
	if len(t.logons) > 100000 {
		t.logons = map[string]logonInfo{}
	}
	t.logons[r.Computer+"|"+r.Get("TargetLogonId")] = logonInfo{lt, e.SourceIP}
	admin := r.Get("ElevatedToken") == "%%1842"
	how, name := logonHow(r, lt)
	e.Summary = fmt.Sprintf("%s logged on %s%s", user, how, fromWhere(r, e.SourceIP))
	if admin {
		e.Summary += " with administrator rights"
	}
	e.Summary += "."
	// An administrator's interactive logon is recorded twice (UAC's full
	// and filtered tokens, linked to each other): report it once, keeping
	// the one with administrator rights.
	if linked := r.Get("TargetLinkedLogonId"); linked != "" && linked != "0x0" {
		a, b := strings.ToLower(r.Get("TargetLogonId")), strings.ToLower(linked)
		if b < a {
			a, b = b, a
		}
		e.DedupeKey, e.Priority = "linkedlogon|"+a+"|"+b, 1
		if admin {
			e.Priority = 2
		}
	}
	e.AddDetail("Logon type", name)
	e.AddDetail("Source address", e.SourceIP)
	e.AddDetail("Source workstation", r.Get("WorkstationName"))
	e.AddDetail("Authentication", r.Get("AuthenticationPackageName"))
	e.AddDetail("Process", r.Get("ProcessName"))
	e.AddDetail("Logon ID", r.Get("TargetLogonId"))
	return e
}

func (t *Translator) logonFailure(r *Raw) *event.Event {
	lt := r.Get("LogonType")
	user := joinAccount(r.Get("TargetDomainName"), r.Get("TargetUserName"), r.Computer)
	if user == "" {
		user = "(no user name given)"
	}
	reason := failureReason(r.Get("Status"), r.Get("SubStatus"))
	e := &event.Event{Category: event.CatFailedLogon, Severity: event.SevLow, Action: "logon_failed",
		User: user, Target: user, Outcome: "failure", SourceIP: cleanIP(r.Get("IpAddress")),
		Process: r.Get("ProcessName"),
		// 4776 is logged alongside 4625 for local accounts; keep this one.
		DedupeKey: "authfail|" + strings.ToLower(user), Priority: 2}
	how, name := logonHow(r, lt)
	e.Summary = fmt.Sprintf("Failed logon for %s %s%s — %s.", user, how, fromWhere(r, e.SourceIP), reason)
	e.AddDetail("Reason", reason)
	e.AddDetail("Logon type", name)
	e.AddDetail("Source address", e.SourceIP)
	e.AddDetail("Source workstation", r.Get("WorkstationName"))
	e.AddDetail("Process", r.Get("ProcessName"))
	e.AddDetail("Status code", r.Get("Status"))
	e.AddDetail("Sub-status code", r.Get("SubStatus"))
	return e
}

func (t *Translator) logoff(r *Raw) *event.Event {
	user := t.account(r, "TargetUserSid", "TargetDomainName", "TargetUserName")
	if t.isServiceAccount(r.Get("TargetUserSid"), r.Get("TargetUserName")) {
		return nil
	}
	e := &event.Event{Category: event.CatLogon, Action: "logoff", User: user, Outcome: "success",
		Summary:   fmt.Sprintf("%s logged off.", user),
		DedupeKey: "logoff|" + strings.ToLower(r.Get("TargetLogonId")), Priority: 2}
	e.AddDetail("Logon ID", r.Get("TargetLogonId"))
	return e
}

// sessionEnded reports the end of a person's session (4634). A logoff the
// person chose is also recorded as 4647, which is kept instead; 4634 alone
// means the session was ended for them (logged off by an administrator,
// or an idle or disconnect time limit).
func (t *Translator) sessionEnded(r *Raw) *event.Event {
	if !interactiveLogon(r.Get("LogonType")) || t.isServiceAccount(r.Get("TargetUserSid"), r.Get("TargetUserName")) {
		return nil
	}
	user := t.account(r, "TargetUserSid", "TargetDomainName", "TargetUserName")
	e := &event.Event{Category: event.CatLogon, Action: "logoff", User: user, Outcome: "success",
		Summary:   fmt.Sprintf("%s's session ended (logged off by the system or an administrator, or it timed out).", user),
		DedupeKey: "logoff|" + strings.ToLower(r.Get("TargetLogonId")), Priority: 1}
	e.AddDetail("Logon type", logonTypeName(r.Get("LogonType")))
	e.AddDetail("Logon ID", r.Get("TargetLogonId"))
	return e
}

// logonHow describes how someone logged on. Logons through the Windows
// OpenSSH server are shown as SSH rather than by their logon type (often
// "network with a clear-text password", which would read as an alarm).
func logonHow(r *Raw, lt string) (phrase, name string) {
	for _, p := range []string{r.Get("LogonProcessName"), r.Get("ProcessName")} {
		if strings.Contains(strings.ToLower(p), "sshd") {
			return "via SSH (OpenSSH)", "SSH (OpenSSH)"
		}
	}
	return logonTypePhrase(lt), logonTypeName(lt)
}

func (t *Translator) rdpSession(r *Raw) *event.Event {
	user := joinAccount(r.Get("AccountDomain"), r.Get("AccountName"), r.Computer)
	client := r.Get("ClientName")
	addr := cleanIP(r.Get("ClientAddress"))
	from := ""
	if client != "" && client != "Unknown" {
		from = " from " + client
		if addr != "" {
			from += " (" + addr + ")"
		}
	} else if addr != "" {
		from = " from " + addr
	}
	e := &event.Event{Category: event.CatLogon, User: user, SourceIP: addr}
	if r.EventID == 4778 {
		e.Action, e.Summary = "session_reconnected", fmt.Sprintf("%s reconnected to a Remote Desktop session%s.", user, from)
	} else {
		e.Action, e.Summary = "session_disconnected", fmt.Sprintf("%s disconnected from a Remote Desktop session%s.", user, from)
	}
	return e
}

func (t *Translator) explicitCreds(r *Raw) *event.Event {
	subj := t.subject(r)
	if t.isServiceAccount(r.Get("SubjectUserSid"), r.Get("SubjectUserName")) {
		return nil
	}
	target := joinAccount(r.Get("TargetDomainName"), r.Get("TargetUserName"), r.Computer)
	if strings.EqualFold(r.Get("TargetUserName"), r.Get("SubjectUserName")) {
		return nil // same account (e.g. mapping a drive with saved creds)
	}
	proc := r.Get("ProcessName")
	e := &event.Event{Category: event.CatPrivileged, Severity: event.SevMedium, Action: "explicit_credentials",
		User: subj, Target: target, Process: proc, SourceIP: cleanIP(r.Get("IpAddress"))}
	e.Summary = fmt.Sprintf("%s used the credentials of %s", subj, target)
	// svchost/lsass/consent are the Windows plumbing behind RunAs and UAC
	// prompts, not the program the person meant to run.
	switch base := strings.ToLower(filepath.Base(winPath(proc))); base {
	case "", "svchost.exe", "lsass.exe", "consent.exe":
	default:
		e.Summary += " to run " + filepath.Base(winPath(proc))
	}
	if srv := r.Get("TargetServerName"); srv != "" && !strings.EqualFold(srv, "localhost") {
		e.Summary += " against " + srv
	}
	e.Summary += " (RunAs / alternate credentials)."
	e.AddDetail("Account used", target)
	e.AddDetail("Target server", r.Get("TargetServerName"))
	e.AddDetail("Process", proc)
	return e
}

func (t *Translator) specialPrivileges(r *Raw) *event.Event {
	if t.isServiceAccount(r.Get("SubjectUserSid"), r.Get("SubjectUserName")) {
		return nil
	}
	user := t.subject(r)
	privs := strings.Fields(r.Get("PrivilegeList"))
	e := &event.Event{Category: event.CatPrivileged, Severity: event.SevLow, Action: "admin_logon", User: user,
		Summary:   fmt.Sprintf("%s logged on with administrator privileges.", user),
		DedupeKey: "4672|" + r.Get("SubjectLogonId")}
	if li, ok := t.logons[r.Computer+"|"+r.Get("SubjectLogonId")]; ok {
		how := logonTypePhrase(li.logonType)
		if li.ip != "" {
			how += " from " + li.ip
		}
		e.SourceIP = li.ip
		e.Summary = fmt.Sprintf("%s logged on %s with administrator privileges.", user, how)
		e.AddDetail("Logon type", logonTypeName(li.logonType))
	}
	var named []string
	for _, p := range privs {
		if d, ok := privilegeNames[p]; ok {
			named = append(named, p+" ("+d+")")
		} else {
			named = append(named, p)
		}
	}
	e.AddDetail("Privileges", strings.Join(named, ", "))
	e.AddDetail("Logon ID", r.Get("SubjectLogonId"))
	return e
}

// auditTamper are command fragments that clear logs or weaken auditing.
var auditTamper = []string{
	"wevtutil cl", "wevtutil.exe cl", "clear-eventlog", "clear-winevent", "remove-eventlog",
	"auditpol /clear", "auditpol /remove", "auditpol.exe /clear", "auditpol.exe /remove",
	"auditpol /set", "auditpol.exe /set", "vssadmin delete shadows", "vssadmin.exe delete shadows",
	"bcdedit /set", "bcdedit.exe /set", "fsutil usn deletejournal",
}

func (t *Translator) processCreated(r *Raw) *event.Event {
	elev := r.Get("TokenElevationType")
	label := r.Get("MandatoryLabel")
	// %%1937 = elevated via UAC. %%1936 ("default") is also used for
	// standard users, so it only counts when the integrity label is High.
	elevated := elev == "%%1937" || label == "S-1-16-12288" || label == "S-1-16-16384"
	if !elevated || t.isServiceAccount(r.Get("SubjectUserSid"), r.Get("SubjectUserName")) {
		return nil
	}
	user := t.subject(r)
	proc := r.Get("NewProcessName")
	cmd := r.Get("CommandLine")
	e := &event.Event{Category: event.CatPrivileged, Severity: event.SevLow, Action: "elevated_process",
		User: user, Process: proc, Command: cmd}
	shown := cmd
	if shown == "" {
		shown = proc
	}
	// PowerShell run with -EncodedCommand (as remote management tools do)
	// hides the real command in base64: show it, and check it for tampering.
	decoded := decodePowerShell(cmd)
	if decoded != "" {
		shown = proc + " (encoded command): " + decoded
	}
	e.Summary = fmt.Sprintf("%s ran with administrator rights: %s", user, shown)
	lc := strings.Join(strings.Fields(strings.ToLower(cmd+" "+decoded)), " ")
	for _, frag := range auditTamper {
		if strings.Contains(lc, frag) {
			e.Severity = event.SevHigh
			e.Action = "audit_tamper_command"
			e.Summary = fmt.Sprintf("%s ran a command that can clear logs or weaken auditing: %s", user, shown)
			break
		}
	}
	e.AddDetail("Program", proc)
	e.AddDetail("Command line", cmd)
	e.AddDetail("PowerShell command (decoded)", decoded)
	e.AddDetail("Started by", r.Get("ParentProcessName"))
	e.AddDetail("Elevation", expandTokens(elev))
	if cmd == "" {
		e.AddDetail("Note", "Command-line auditing is off, so only the program name is known.")
	}
	return e
}

func (t *Translator) serviceInstalled(r *Raw, name, path, account, by string) *event.Event {
	e := &event.Event{Category: event.CatOther, Severity: event.SevMedium, Action: "service_installed",
		User: by, Target: name, Process: path, DedupeKey: "svc|" + strings.ToLower(name), Priority: 1}
	e.Summary = fmt.Sprintf("A new service was installed: %s (%s)", name, path)
	if by != "" {
		e.Summary += " by " + by
	}
	e.Summary += "."
	e.AddDetail("Service name", name)
	e.AddDetail("Program", path)
	e.AddDetail("Runs as", account)
	return e
}

func (t *Translator) scheduledTask(r *Raw) *event.Event {
	if t.isServiceAccount(r.Get("SubjectUserSid"), r.Get("SubjectUserName")) && r.EventID != 4698 {
		return nil // Windows updates its own tasks constantly
	}
	user := t.subject(r)
	task := r.Get("TaskName")
	verbs := map[int]string{4698: "created", 4699: "deleted", 4700: "enabled", 4701: "disabled", 4702: "updated"}
	sev := event.SevLow
	if r.EventID == 4698 {
		sev = event.SevMedium
	}
	e := &event.Event{Category: event.CatOther, Severity: sev, Action: "scheduled_task_" + verbs[r.EventID],
		User: user, Target: task,
		Summary: fmt.Sprintf("Scheduled task %s was %s by %s.", task, verbs[r.EventID], orUnknown(user))}
	e.AddDetail("Task", task)
	if cmd := taskCommand(r.Get("TaskContent")); cmd != "" {
		e.AddDetail("Runs", cmd)
	}
	return e
}

// taskCommand pulls <Command> and <Arguments> out of a task definition.
func taskCommand(xmlText string) string {
	get := func(tag string) string {
		i := strings.Index(xmlText, "<"+tag+">")
		j := strings.Index(xmlText, "</"+tag+">")
		if i < 0 || j < i {
			return ""
		}
		return strings.TrimSpace(xmlText[i+len(tag)+2 : j])
	}
	return strings.TrimSpace(get("Command") + " " + get("Arguments"))
}

func (t *Translator) auditPolicyChanged(r *Raw) *event.Event {
	user := t.subject(r)
	sub := AuditSubcategories[strings.ToUpper(r.Get("SubcategoryGuid"))]
	if sub == "" {
		sub = expandTokens(r.Get("SubcategoryId"))
	}
	changes := expandTokens(r.Get("AuditPolicyChanges"))
	sev := event.SevHigh
	by := user
	if t.isServiceAccount(r.Get("SubjectUserSid"), r.Get("SubjectUserName")) {
		sev = event.SevMedium // normally Group Policy being applied
		by = "the system (usually Group Policy)"
	}
	e := &event.Event{Category: event.CatIntegrity, Severity: sev, Action: "audit_policy_changed",
		User: user, Target: sub,
		Summary: fmt.Sprintf("Audit policy for \"%s\" was changed by %s: %s.", sub, by, strings.ToLower(changes))}
	e.AddDetail("Category", expandTokens(r.Get("CategoryId")))
	e.AddDetail("Subcategory", sub)
	e.AddDetail("Change", changes)
	return e
}

func (t *Translator) timeChanged(r *Raw) *event.Event {
	prev, err1 := time.Parse(time.RFC3339Nano, r.Get("PreviousTime"))
	next, err2 := time.Parse(time.RFC3339Nano, r.Get("NewTime"))
	svc := t.isServiceAccount(r.Get("SubjectUserSid"), r.Get("SubjectUserName"))
	var delta time.Duration
	if err1 == nil && err2 == nil {
		delta = next.Sub(prev)
		// Routine clock sync by the Windows Time service.
		if svc && delta.Abs() < 5*time.Minute {
			return nil
		}
	}
	user := t.subject(r)
	e := &event.Event{Category: event.CatIntegrity, Severity: event.SevMedium, Action: "time_changed",
		User: user, Process: r.Get("ProcessName")}
	if err1 == nil && err2 == nil {
		e.Summary = fmt.Sprintf("System time was changed by %s, moving the clock %s %s.", orUnknown(user), roundDur(delta.Abs()), map[bool]string{true: "forward", false: "back"}[delta >= 0])
	} else {
		e.Summary = fmt.Sprintf("System time was changed by %s.", orUnknown(user))
	}
	e.AddDetail("Previous time", r.Get("PreviousTime"))
	e.AddDetail("New time", r.Get("NewTime"))
	e.AddDetail("Process", r.Get("ProcessName"))
	return e
}

func (t *Translator) accountChange(r *Raw) *event.Event {
	by := t.subject(r)
	target := joinAccount(r.Get("TargetDomainName"), r.Get("TargetUserName"), r.Computer)
	type info struct {
		action, verb string
		sev          event.Severity
	}
	m := map[int]info{
		4720: {"account_created", "created", event.SevMedium},
		4722: {"account_enabled", "enabled", event.SevMedium},
		4723: {"password_change", "", event.SevLow},
		4724: {"password_reset", "", event.SevMedium},
		4725: {"account_disabled", "disabled", event.SevMedium},
		4726: {"account_deleted", "deleted", event.SevMedium},
		4738: {"account_changed", "changed", event.SevLow},
		4767: {"account_unlocked", "unlocked", event.SevLow},
		4781: {"account_renamed", "", event.SevMedium},
	}[r.EventID]
	e := &event.Event{Category: event.CatAccount, Severity: m.sev, Action: m.action, User: by, Target: target}
	if r.AuditFailure() {
		e.Outcome = "failure"
	}
	switch r.EventID {
	case 4723:
		if strings.EqualFold(r.Get("TargetUserName"), r.Get("SubjectUserName")) {
			e.Summary = fmt.Sprintf("%s changed their own password.", target)
		} else {
			e.Summary = fmt.Sprintf("%s changed the password of %s.", by, target)
		}
	case 4724:
		e.Summary = fmt.Sprintf("%s reset the password of %s.", by, target)
	case 4781:
		e.Summary = fmt.Sprintf("%s renamed account %s to %s.", by, r.Get("OldTargetUserName"), r.Get("NewTargetUserName"))
		e.Target = r.Get("NewTargetUserName")
	default:
		e.Summary = fmt.Sprintf("%s %s the user account %s.", by, m.verb, target)
	}
	if e.Outcome == "failure" {
		e.Summary = strings.TrimSuffix(e.Summary, ".") + " — the attempt failed."
	}
	e.AddDetail("Account", target)
	e.AddDetail("Account SID", r.Get("TargetSid"))
	e.AddDetail("Display name", r.Get("DisplayName"))
	if uac := r.Get("UserAccountControl"); uac != "" {
		e.AddDetail("Account flags changed", expandTokens(uac))
	}
	if t.sidNames != nil && r.Get("TargetSid") != "" && r.Get("TargetUserName") != "" {
		t.sidNames[r.Get("TargetSid")] = target
	}
	return e
}

func (t *Translator) groupLifecycle(r *Raw) *event.Event {
	by := t.subject(r)
	group := r.Get("TargetUserName")
	verb := map[int]string{4727: "created", 4731: "created", 4754: "created", 4730: "deleted", 4734: "deleted", 4758: "deleted"}[r.EventID]
	sev := event.SevLow
	if verb == "deleted" {
		sev = event.SevMedium
	}
	return &event.Event{Category: event.CatAccount, Severity: sev, Action: "group_" + verb, User: by, Target: group,
		Summary: fmt.Sprintf("%s %s the security group %s.", by, verb, group)}
}

func (t *Translator) groupMembership(r *Raw) *event.Event {
	by := t.subject(r)
	group := r.Get("TargetUserName")
	member := t.memberName(r.Get("MemberName"), r.Get("MemberSid"))
	added := r.EventID == 4728 || r.EventID == 4732 || r.EventID == 4756
	priv := isPrivilegedGroup(group, r.Get("TargetSid"))
	e := &event.Event{Category: event.CatAccount, User: by, Target: member}
	if added {
		e.Action, e.Severity = "group_member_added", event.SevMedium
		e.Summary = fmt.Sprintf("%s added %s to the group %s.", by, member, group)
		if priv {
			e.Severity = event.SevHigh
			e.Summary = fmt.Sprintf("%s added %s to the privileged group %s.", by, member, group)
		}
	} else {
		e.Action, e.Severity = "group_member_removed", event.SevMedium
		e.Summary = fmt.Sprintf("%s removed %s from the group %s.", by, member, group)
	}
	e.AddDetail("Group", group)
	e.AddDetail("Member", member)
	e.AddDetail("Member SID", r.Get("MemberSid"))
	if priv {
		e.AddDetail("Why it matters", "Members of this group have administrative or remote access.")
	}
	return e
}

func (t *Translator) kerberosFailure(r *Raw) *event.Event {
	user := r.Get("TargetUserName")
	code := normHex(r.Get("Status"))
	reason, ok := kerberosFailure[code]
	if !ok {
		reason = "Kerberos error " + code
	}
	ip := cleanIP(r.Get("IpAddress"))
	e := &event.Event{Category: event.CatFailedLogon, Severity: event.SevLow, Action: "logon_failed",
		User: user, Target: user, Outcome: "failure", SourceIP: ip,
		Summary: fmt.Sprintf("Failed domain (Kerberos) logon for %s%s — %s.", user, fromIP(ip), reason)}
	e.AddDetail("Reason", reason)
	e.AddDetail("Source address", ip)
	e.AddDetail("Status code", r.Get("Status"))
	return e
}

func (t *Translator) ntlmValidation(r *Raw) *event.Event {
	status := normHex(r.Get("Status"))
	if status == "0x0" || status == "" {
		return nil
	}
	user := r.Get("TargetUserName")
	ws := r.Get("Workstation")
	reason := failureReason(status, "")
	e := &event.Event{Category: event.CatFailedLogon, Severity: event.SevLow, Action: "logon_failed",
		User: user, Target: user, Outcome: "failure",
		DedupeKey: "authfail|" + strings.ToLower(user), Priority: 1}
	e.Summary = fmt.Sprintf("Password check failed for %s", user)
	if ws != "" && !strings.EqualFold(ws, shortHost(r.Computer)) {
		e.Summary += " from workstation " + ws
	}
	e.Summary += " — " + reason + "."
	e.AddDetail("Reason", reason)
	e.AddDetail("Workstation", ws)
	e.AddDetail("Status code", r.Get("Status"))
	return e
}

// removableAccess handles 4663/4656 events from the Removable Storage
// audit subcategory.
func (t *Translator) removableAccess(r *Raw) *event.Event {
	if r.Task != taskRemovableStorage {
		return nil
	}
	user := t.subject(r)
	obj := r.Get("ObjectName")
	if t.MapDevicePath != nil {
		obj = t.MapDevicePath(obj)
	}
	proc := r.Get("ProcessName")
	access := r.Get("AccessList")
	failed := r.AuditFailure()
	op := fileOperation(access)
	if op == "" && !failed {
		return nil // metadata-only access (attributes, permissions)
	}
	e := &event.Event{Category: event.CatRemovable, User: user, Target: obj, Process: proc}
	switch {
	case failed:
		e.Action, e.Severity, e.Outcome = "removable_access_denied", event.SevMedium, "failure"
		e.Summary = fmt.Sprintf("%s was blocked from accessing removable media: %s", user, obj)
	case op == "write":
		e.Action, e.Severity = "removable_write", event.SevMedium
		e.Summary = fmt.Sprintf("%s wrote to removable media: %s", user, obj)
	case op == "delete":
		e.Action, e.Severity = "removable_delete", event.SevMedium
		e.Summary = fmt.Sprintf("%s deleted from removable media: %s", user, obj)
	case op == "execute":
		e.Action, e.Severity = "removable_execute", event.SevMedium
		e.Summary = fmt.Sprintf("%s ran a program from removable media: %s", user, obj)
	default:
		e.Action, e.Severity = "removable_read", event.SevLow
		e.Summary = fmt.Sprintf("%s read from removable media: %s", user, obj)
	}
	if proc != "" {
		e.Summary += " (using " + filepath.Base(winPath(proc)) + ")"
	}
	e.Summary += "."
	e.DedupeKey = "rm|" + e.Action + "|" + strings.ToLower(user+"|"+obj)
	e.AddDetail("File", obj)
	e.AddDetail("Access", expandTokens(access))
	e.AddDetail("Program", proc)
	return e
}

// fileOperation classifies an AccessList into write, delete, execute,
// read, or "" (metadata only).
func fileOperation(access string) string {
	has := func(tok string) bool { return strings.Contains(access, tok) }
	switch {
	case has("%%4417") || has("%%4418") || has("%%4420") || has("%%4424"):
		return "write"
	case has("%%1537") || has("%%4422"):
		return "delete"
	case has("%%4421"):
		return "execute"
	case has("%%4416"):
		return "read"
	}
	return ""
}

// pnpDevice handles 6416 "A new external device was recognized". Only
// storage and portable devices are reported.
func (t *Translator) pnpDevice(r *Raw) *event.Event {
	id := r.Get("DeviceId")
	class := r.Get("ClassName")
	d := parseDeviceID(id)
	if !d.storage && !strings.EqualFold(class, "WPD") && !strings.EqualFold(class, "DiskDrive") && !strings.EqualFold(class, "CDROM") {
		return nil
	}
	desc := r.Get("DeviceDescription")
	name := strings.TrimSpace(strings.TrimSuffix(desc, " USB Device"))
	if name == "" {
		name = d.name()
	}
	e := &event.Event{Category: event.CatRemovable, Severity: event.SevMedium, Action: "usb_connected",
		User: t.subject(r), Target: name, DedupeKey: "usb|" + d.key(id), Priority: 1}
	e.Summary = fmt.Sprintf("Removable device connected: %s%s.", name, d.serialText())
	e.AddDetail("Device", desc)
	e.AddDetail("Vendor", d.vendor)
	e.AddDetail("Product", d.product)
	e.AddDetail("Serial number", d.serial)
	e.AddDetail("Device class", class)
	e.AddDetail("Device ID", id)
	return e
}

// ---------------------------------------------------------------- System

func (t *Translator) system(r *Raw) *event.Event {
	switch {
	case r.EventID == 104 && strings.Contains(r.Provider, "Eventlog"):
		u := joinAccount(r.Get("SubjectDomainName"), r.Get("SubjectUserName"), r.Computer)
		ch := r.Get("Channel")
		if ch == "" {
			ch = "An event"
		} else {
			ch = "The " + ch
		}
		e := &event.Event{Category: event.CatIntegrity, Severity: event.SevHigh, Action: "log_cleared", User: u,
			Target: r.Get("Channel"), Summary: fmt.Sprintf("%s log was cleared by %s.", ch, orUnknown(u))}
		e.AddDetail("Backup file", r.Get("BackupPath"))
		return e
	case r.EventID == 7045:
		acct := r.Get("AccountName")
		by := ""
		if r.UserSID != "" && !t.isServiceAccount(r.UserSID, "") {
			by = t.resolve(r.UserSID)
		}
		return t.serviceInstalled(r, r.Get("ServiceName"), r.Get("ImagePath"), acct, by)
	case r.EventID == 1074:
		user := qualifiedAccount(r.Get("param7"), r.Computer)
		kind := strings.ToLower(r.Get("param5"))
		if kind == "" {
			kind = "restart/shutdown"
		}
		proc := r.Get("param1")
		e := &event.Event{Category: event.CatIntegrity, Action: "shutdown_initiated", User: user, Process: proc,
			Summary: fmt.Sprintf("%s initiated a %s", orUnknown(user), kind)}
		if proc != "" {
			if i := strings.Index(proc, " ("); i > 0 {
				proc = proc[:i] // "C:\...\shutdown.exe (WS-07)"
			}
			e.Summary += " using " + filepath.Base(winPath(proc))
		}
		if reason := r.Get("param3"); reason != "" {
			e.Summary += " — " + reason
		}
		e.Summary += "."
		e.AddDetail("Reason", r.Get("param3"))
		e.AddDetail("Comment", r.Get("param6"))
		return e
	case r.EventID == 6005 && r.Provider == "EventLog":
		return &event.Event{Category: event.CatIntegrity, Action: "system_start", DedupeKey: "boot", Priority: 2,
			Summary: "The system started (event log service started)."}
	case r.EventID == 6006 && r.Provider == "EventLog":
		return &event.Event{Category: event.CatIntegrity, Action: "system_stop",
			Summary: "The system shut down cleanly (event log service stopped)."}
	case r.EventID == 6008 && r.Provider == "EventLog":
		e := &event.Event{Category: event.CatIntegrity, Severity: event.SevLow, Action: "unexpected_shutdown",
			Summary: "The previous shutdown was unexpected (power loss, crash or forced power-off)."}
		if tm, dt := r.Get("Data0"), r.Get("Data1"); tm != "" {
			e.Summary = fmt.Sprintf("The system shut down unexpectedly at %s %s (power loss, crash or forced power-off).", dt, tm)
		}
		return e
	}
	return nil
}

// ---------------------------------------------------------------- USB logs

// partition handles Partition/Diagnostic 1006, logged whenever a disk
// arrives or leaves. It records vendor, model, serial and size and is on
// by default in Windows 10/11.
func (t *Translator) partition(r *Raw) *event.Event {
	if r.EventID != 1006 {
		return nil
	}
	if strings.EqualFold(r.Get("IsSystem"), "true") || strings.EqualFold(r.Get("IsBoot"), "true") {
		return nil
	}
	bt := r.Get("BusType")
	if !removableBus(bt) && !virtualBus(bt) {
		return nil
	}
	name := strings.TrimSpace(r.Get("Manufacturer") + " " + r.Get("Model"))
	// Prefer the USB serial from the parent device ID so the same stick
	// matches its Kernel-PnP/6416 events; fall back to the disk serial.
	d := parseDeviceID(r.Get("ParentId"))
	serial := d.serial
	if serial == "" {
		serial = strings.TrimSpace(r.Get("SerialNumber"))
	}
	if name == "" {
		name = d.name()
	}
	if name == "" {
		name = "unnamed device"
	}
	capBytes, _ := strconv.ParseUint(r.Get("Capacity"), 10, 64)
	e := &event.Event{Category: event.CatRemovable, Target: name}
	bus := busTypes[bt]
	key := strings.ToLower(serial)
	if key == "" {
		key = strings.ToLower(name)
	}
	if capBytes == 0 {
		e.Action, e.Severity = "usb_disconnected", event.SevInfo
		e.Summary = fmt.Sprintf("Removable storage disconnected: %s%s.", name, serialSuffix(serial))
		e.DedupeKey = "usboff|" + key
	} else {
		e.Action, e.Severity = "usb_connected", event.SevMedium
		e.DedupeKey, e.Priority = "usb|"+key, 3
		if virtualBus(bt) {
			e.Action = "virtual_disk_mounted"
			e.Summary = fmt.Sprintf("A virtual disk (ISO/VHD file) was mounted: %s, %s.", name, humanBytes(capBytes))
			e.DedupeKey = "vd|" + key
		} else {
			e.Summary = fmt.Sprintf("%s storage connected: %s%s, %s.", bus, name, serialSuffix(serial), humanBytes(capBytes))
		}
	}
	e.AddDetail("Connection", bus)
	e.AddDetail("Manufacturer", r.Get("Manufacturer"))
	e.AddDetail("Model", r.Get("Model"))
	e.AddDetail("Serial number", serial)
	if ds := strings.TrimSpace(r.Get("SerialNumber")); ds != "" && ds != serial {
		e.AddDetail("Disk serial number", ds)
	}
	if capBytes > 0 {
		e.AddDetail("Capacity", humanBytes(capBytes))
	}
	e.AddDetail("Device ID", r.Get("ParentId"))
	e.Fields = trimFields(r.Data, "Mbr", "Vbr0", "Vbr1", "Vbr2", "Vbr3", "PartitionTable", "UserData")
	return e
}

// kernelPnP handles Kernel-PnP/Configuration 400 (device configured),
// logged when a device is set up, including its first connection.
func (t *Translator) kernelPnP(r *Raw) *event.Event {
	if r.EventID != 400 {
		return nil
	}
	id := r.Get("DeviceInstanceId")
	d := parseDeviceID(id)
	if !d.storage {
		return nil
	}
	name := d.name()
	e := &event.Event{Category: event.CatRemovable, Severity: event.SevMedium, Action: "usb_connected", Target: name,
		DedupeKey: "usb|" + d.key(id), Priority: 2,
		Summary: fmt.Sprintf("Removable storage device configured (connected): %s%s.", name, d.serialText())}
	e.AddDetail("Vendor", d.vendor)
	e.AddDetail("Product", d.product)
	e.AddDetail("Serial number", d.serial)
	e.AddDetail("Driver", r.Get("DriverName"))
	e.AddDetail("Device ID", id)
	return e
}

// driverFrameworks handles DriverFrameworks-UserMode 2003/2100 (off by
// default; STIG-hardened systems often enable it).
func (t *Translator) driverFrameworks(r *Raw) *event.Event {
	if r.EventID != 2003 && r.EventID != 2100 && r.EventID != 2102 {
		return nil
	}
	var id string
	for _, v := range r.Data {
		if strings.Contains(strings.ToUpper(v), "USBSTOR") {
			id = v
			break
		}
	}
	if id == "" {
		return nil
	}
	d := parseDeviceID(id)
	name := d.name()
	if r.EventID == 2003 {
		return &event.Event{Category: event.CatRemovable, Severity: event.SevMedium, Action: "usb_connected", Target: name,
			DedupeKey: "usb|" + d.key(id), Priority: 0,
			Summary: fmt.Sprintf("USB storage connected: %s%s.", name, d.serialText())}
	}
	return &event.Event{Category: event.CatRemovable, Action: "usb_disconnected", Target: name,
		DedupeKey: "usboff|" + d.key(id),
		Summary:   fmt.Sprintf("USB storage disconnected: %s%s.", name, d.serialText())}
}

// ---------------------------------------------------------------- Defender

func (t *Translator) defender(r *Raw) *event.Event {
	threat := r.Get("Threat Name")
	path := strings.TrimPrefix(r.Get("Path"), "file:_")
	user := qualifiedAccount(r.Get("Detection User"), r.Computer)
	switch r.EventID {
	case 1116:
		e := &event.Event{Category: event.CatOther, Severity: event.SevHigh, Action: "malware_detected",
			User: user, Target: threat,
			Summary: fmt.Sprintf("Microsoft Defender detected malware: %s in %s.", threat, orUnknown(path))}
		e.AddDetail("Severity", r.Get("Severity Name"))
		e.AddDetail("Category", r.Get("Category Name"))
		e.AddDetail("File", path)
		e.AddDetail("Process", r.Get("Process Name"))
		return e
	case 1117:
		return &event.Event{Category: event.CatOther, Severity: event.SevMedium, Action: "malware_action",
			User: user, Target: threat,
			Summary: fmt.Sprintf("Microsoft Defender took action on %s: %s.", threat, orUnknown(r.Get("Action Name")))}
	case 1118, 1119:
		return &event.Event{Category: event.CatOther, Severity: event.SevHigh, Action: "malware_action_failed",
			User: user, Target: threat,
			Summary: fmt.Sprintf("Microsoft Defender FAILED to remove %s from %s.", threat, orUnknown(path))}
	case 5001:
		return &event.Event{Category: event.CatOther, Severity: event.SevHigh, Action: "av_disabled",
			Summary: "Microsoft Defender real-time protection was turned off."}
	case 5010, 5012:
		return &event.Event{Category: event.CatOther, Severity: event.SevHigh, Action: "av_disabled",
			Summary: "Microsoft Defender scanning was turned off."}
	}
	return nil
}

// ---------------------------------------------------------------- PowerShell

// psRule is one kind of PowerShell script worth reporting. A script block
// matches when every pattern in find matches somewhere in it; the line
// holding the first pattern's match is shown in the report.
type psRule struct {
	action string
	sev    event.Severity
	cat    event.Category
	what   string // completes "jsmith ran a PowerShell script that …"
	find   []*regexp.Regexp
}

// psRules are the script blocks that are reported, checked in order (the
// first match wins). Everything else PowerShell records is routine:
// management tools, logon scripts and modules loading run thousands of
// script blocks a day. Matching ignores case.
var psRules = []psRule{
	// Clearing logs or weakening auditing: the same commands that are
	// flagged on a command line (auditTamper), plus PowerShell's own.
	{"powershell_tamper", event.SevHigh, event.CatIntegrity, "can clear logs or weaken auditing",
		psPatterns(tamperPattern(), `limit-eventlog`, `wevtutil(?:\.exe)?\s+clear-log`,
			`stop-service\s+(?:-name\s+)?['"]?eventlog\b`)},

	// Turning Microsoft Defender off, excluding files from scanning, or
	// removing it ($false re-enables, so only $true/1 counts).
	{"powershell_av_tamper", event.SevHigh, event.CatOther, "turns off or weakens Microsoft Defender",
		psPatterns(`set-mppreference\b.*-disable\w+(?:\s+|:)(?:\$true|1)\b`,
			`(?:add|set)-mppreference\b.*-exclusion(?:path|process|extension)\b`,
			`(?:uninstall|remove)-windowsfeature\b.*windows-defender`)},

	// Switching off the Antimalware Scan Interface, which lets Defender
	// see the scripts PowerShell runs.
	{"powershell_amsi_bypass", event.SevHigh, event.CatOther, "tries to switch off malware scanning of scripts (AMSI bypass)",
		psPatterns(`amsiutils|amsiinitfailed`)},

	// Tools that steal passwords and logon tokens from memory or Group
	// Policy files.
	{"powershell_credential", event.SevHigh, event.CatOther, "uses a password-stealing tool",
		psPatterns(`mimikatz|\bsekurlsa\b|\blsadump\b|get-gpppassword`,
			`out-minidump.*lsass|lsass.*out-minidump`)},

	// Download cradles: code fetched from the network and run straight
	// away, without ever being saved where it could be scanned.
	{"powershell_download", event.SevHigh, event.CatOther, "downloads and runs code",
		[]*regexp.Regexp{psPattern(`net\.webclient|downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|start-bitstransfer`),
			psPattern(`invoke-expression|\biex\b`)}},
	{"powershell_download", event.SevHigh, event.CatOther, "decodes hidden (base64) code and runs it",
		[]*regexp.Regexp{psPattern(`frombase64string`), psPattern(`invoke-expression|\biex\b`)}},
}

// psPattern compiles a case-insensitive pattern.
func psPattern(p string) *regexp.Regexp { return regexp.MustCompile(`(?i)` + p) }

// psPatterns is one pattern matching any of the alternatives.
func psPatterns(alts ...string) []*regexp.Regexp {
	return []*regexp.Regexp{psPattern(`(?:` + strings.Join(alts, `)|(?:`) + `)`)}
}

// tamperPattern matches the auditTamper commands with any spacing.
func tamperPattern() string {
	var alts []string
	for _, frag := range auditTamper {
		alts = append(alts, strings.ReplaceAll(regexp.QuoteMeta(frag), " ", `\s+`))
	}
	return strings.Join(alts, "|")
}

// powerShell handles PowerShell/Operational 4104 (Script Block Logging).
// Only suspicious script blocks are reported: those PowerShell itself
// logs as warnings, and those matching psRules. Module logging (4103) is
// skipped: it repeats what the script blocks show, at great volume.
func (t *Translator) powerShell(r *Raw) *event.Event {
	if r.EventID != 4104 {
		return nil
	}
	text := r.Get("ScriptBlockText")
	var rule *psRule
	var line string
	for i := range psRules {
		if l, ok := psMatch(&psRules[i], text); ok {
			rule, line = &psRules[i], l
			break
		}
	}
	name := scriptName(text, r.Get("Path"))
	var flaggedFor string
	if rule == nil {
		if r.Level != 3 {
			return nil
		}
		// Windows logs a script block as a warning, even when Script Block
		// Logging is off, when it uses commands attackers favour. Windows'
		// own modules do too (the cmdlets it generates for Defender,
		// networking and the like), so those are left out.
		if WindowsModule(text, r.Get("Path")) {
			return nil
		}
		rule = &psRule{action: "powershell_suspicious", sev: event.SevMedium, cat: event.CatOther,
			what: "PowerShell itself flagged as suspicious"}
		flaggedFor, line = suspiciousWord(text)
		if line == "" {
			line = firstLine(text)
		}
	}
	user := t.resolve(r.UserSID)
	e := &event.Event{Category: rule.cat, Severity: rule.sev, Action: rule.action, User: user, Target: name}
	switch {
	case flaggedFor != "":
		e.Summary = fmt.Sprintf("%s ran %s, which PowerShell flagged as suspicious for using %s", orUnknown(user), name, flaggedFor)
	case rule.action == "powershell_suspicious":
		e.Summary = fmt.Sprintf("%s ran %s, which PowerShell flagged as suspicious", orUnknown(user), name)
	default:
		e.Summary = fmt.Sprintf("%s ran %s, which %s", orUnknown(user), name, rule.what)
		if line != "" {
			e.Summary += ": " + clip(line, 120)
		}
	}
	if !strings.HasSuffix(e.Summary, ".") {
		e.Summary += "."
	}
	// A large script is logged in parts sharing one ID: matching parts are
	// reported once.
	if id := r.Get("ScriptBlockId"); id != "" {
		e.DedupeKey = "psblock|" + strings.ToLower(id)
		e.Priority = rule.sev.Rank()
	}
	e.AddDetail("Script", name)
	if flaggedFor != "" {
		e.AddDetail("Flagged for", flaggedFor)
	}
	e.AddDetail("Matched line", clip(line, 500))
	e.AddDetail("Script (excerpt)", clip(strings.TrimSpace(text), 2000))
	if n, total := r.Get("MessageNumber"), r.Get("MessageTotal"); total != "" && total != "1" {
		e.AddDetail("Script part", n+" of "+total)
	}
	e.AddDetail("Script path", r.Get("Path"))
	e.AddDetail("Script block ID", r.Get("ScriptBlockId"))
	if r.Level == 3 && rule.action != "powershell_suspicious" {
		e.AddDetail("Note", "PowerShell also flagged this script as suspicious.")
	}
	// The whole script is in the original log; keep only the excerpt.
	e.Fields = trimFields(r.Data, "ScriptBlockText")
	return e
}

// psMatch reports whether every pattern of rule matches text, and returns
// the line holding the first pattern's match.
func psMatch(rule *psRule, text string) (string, bool) {
	if text == "" || len(rule.find) == 0 {
		return "", false
	}
	loc := rule.find[0].FindStringIndex(text)
	if loc == nil {
		return "", false
	}
	for _, re := range rule.find[1:] {
		if !re.MatchString(text) {
			return "", false
		}
	}
	start := strings.LastIndexByte(text[:loc[0]], '\n') + 1
	end := len(text)
	if i := strings.IndexByte(text[loc[0]:], '\n'); i >= 0 {
		end = loc[0] + i
	}
	return strings.TrimSpace(text[start:end]), true
}

// firstLine returns the first non-blank line of s.
func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}

// clip shortens s to n characters, marking the cut.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimSpace(string(r[:n])) + " …"
}

// ---------------------------------------------------------------- helpers

// account builds DOMAIN\user from the named fields, resolving the SID if
// the name is missing.
func (t *Translator) account(r *Raw, sidF, domF, userF string) string {
	u := joinAccount(r.Get(domF), r.Get(userF), r.Computer)
	if u == "" {
		u = t.resolve(r.Get(sidF))
	}
	return u
}

func (t *Translator) subject(r *Raw) string {
	// Windows names the computer account (WORKGROUP\HOST$) for actions
	// taken by the system itself; say "SYSTEM" as people know it.
	switch r.Get("SubjectUserSid") {
	case "S-1-5-18", "S-1-5-19", "S-1-5-20":
		return wellKnownSIDs[r.Get("SubjectUserSid")]
	}
	return t.account(r, "SubjectUserSid", "SubjectDomainName", "SubjectUserName")
}

func (t *Translator) resolve(sid string) string {
	if sid == "" {
		return ""
	}
	if n, ok := wellKnownSIDs[sid]; ok {
		return n
	}
	if n, ok := t.sidNames[sid]; ok {
		return n
	}
	if t.ResolveSID != nil {
		if n := t.ResolveSID(sid); n != "" {
			t.sidNames[sid] = n
			return n
		}
	}
	return sid
}

// learnSIDs remembers SID→name pairs seen in events so later events that
// only carry a SID (e.g. group membership) can show a name.
func (t *Translator) learnSIDs(r *Raw) {
	for _, p := range [][3]string{
		{"TargetUserSid", "TargetDomainName", "TargetUserName"},
		{"SubjectUserSid", "SubjectDomainName", "SubjectUserName"},
	} {
		sid, name := r.Get(p[0]), r.Get(p[2])
		if sid != "" && name != "" && strings.HasPrefix(sid, "S-1-5-21-") {
			t.sidNames[sid] = joinAccount(r.Get(p[1]), name, r.Computer)
		}
	}
}

func (t *Translator) memberName(dn, sid string) string {
	if dn != "" {
		if strings.HasPrefix(strings.ToUpper(dn), "CN=") {
			cn := dn[3:]
			if i := strings.Index(cn, ","); i >= 0 {
				cn = cn[:i]
			}
			return cn
		}
		return dn
	}
	return t.resolve(sid)
}

// isServiceAccount reports built-in, service, virtual and computer
// accounts, whose routine activity is left out of the report.
func (t *Translator) isServiceAccount(sid, name string) bool {
	switch sid {
	case "S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-7", "S-1-0-0":
		return true
	}
	for _, p := range []string{"S-1-5-80-", "S-1-5-82-", "S-1-5-90-", "S-1-5-96-"} {
		if strings.HasPrefix(sid, p) {
			return true
		}
	}
	n := strings.ToUpper(name)
	if strings.HasSuffix(n, "$") {
		return true
	}
	switch n {
	case "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON":
		return true
	}
	return strings.HasPrefix(n, "DWM-") || strings.HasPrefix(n, "UMFD-")
}

// qualifiedAccount normalizes a "DOMAIN\user" string.
func qualifiedAccount(s, computer string) string {
	if i := strings.Index(s, `\`); i >= 0 {
		return joinAccount(s[:i], s[i+1:], computer)
	}
	return joinAccount("", s, computer)
}

// joinAccount returns DOMAIN\user, or just user for local accounts and
// NT AUTHORITY.
func joinAccount(domain, user, computer string) string {
	user = strings.TrimSpace(user)
	domain = strings.TrimSpace(domain)
	if user == "" || user == "-" {
		return ""
	}
	if domain == "" || domain == "-" || strings.EqualFold(domain, "NT AUTHORITY") ||
		strings.EqualFold(domain, shortHost(computer)) || strings.EqualFold(domain, "Builtin") {
		return user
	}
	return domain + `\` + user
}

func shortHost(fqdn string) string {
	if i := strings.Index(fqdn, "."); i > 0 {
		return strings.ToUpper(fqdn[:i])
	}
	return strings.ToUpper(fqdn)
}

func cleanIP(ip string) string {
	ip = strings.TrimPrefix(strings.TrimSpace(ip), "::ffff:")
	switch ip {
	case "", "-", "::1", "127.0.0.1", "0.0.0.0", "::":
		return ""
	}
	return ip
}

func fromWhere(r *Raw, ip string) string {
	if ip != "" {
		return " from " + ip
	}
	if ws := r.Get("WorkstationName"); ws != "" && !strings.EqualFold(ws, shortHost(r.Computer)) {
		return " from workstation " + ws
	}
	return ""
}

func fromIP(ip string) string {
	if ip == "" {
		return ""
	}
	return " from " + ip
}

func orUnknown(s string) string {
	if s == "" {
		return "an unknown account"
	}
	return s
}

// winPath lets filepath.Base split Windows paths on any OS.
func winPath(p string) string { return strings.ReplaceAll(p, `\`, "/") }

func serialSuffix(s string) string {
	if s == "" {
		return ""
	}
	return " (serial " + s + ")"
}

func humanBytes(b uint64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d bytes", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func roundDur(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%.0f days", d.Hours()/24)
	case d >= time.Hour:
		return fmt.Sprintf("%.1f hours", d.Hours())
	case d >= time.Minute:
		return fmt.Sprintf("%.0f minutes", d.Minutes())
	}
	return fmt.Sprintf("%.0f seconds", d.Seconds())
}

func trimFields(in map[string]string, drop ...string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		skip := false
		for _, d := range drop {
			if strings.HasPrefix(k, d) {
				skip = true
				break
			}
		}
		if !skip {
			out[k] = v
		}
	}
	return out
}

// device is what can be read from a Windows device instance ID such as
// USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\4C530001231109115405&0
type device struct {
	vendor, product, serial string
	storage                 bool
}

func parseDeviceID(id string) device {
	var d device
	up := strings.ToUpper(id)
	// DriverFrameworks uses '#' where the registry uses '\'.
	norm := strings.ReplaceAll(id, "#", `\`)
	switch {
	case strings.Contains(up, "USBSTOR"):
		d.storage = true
	case strings.HasPrefix(up, `SWD\WPDBUSENUM`) || strings.HasPrefix(up, `WPD`):
		d.storage = true
	case strings.HasPrefix(up, `SCSI\DISK`) && strings.Contains(up, "USB"):
		d.storage = true
	}
	parts := strings.Split(norm, `\`)
	for _, p := range parts {
		for _, f := range strings.Split(p, "&") {
			lf := strings.ToLower(f)
			switch {
			case strings.HasPrefix(lf, "ven_") && d.vendor == "":
				d.vendor = strings.ReplaceAll(strings.Trim(f[4:], "_ "), "_", " ")
			case strings.HasPrefix(lf, "prod_") && d.product == "":
				d.product = strings.ReplaceAll(strings.Trim(f[5:], "_ "), "_", " ")
			}
		}
	}
	// The last part of ENUMERATOR\HARDWARE-ID\INSTANCE is the device serial
	// when the device reports one. Windows-generated instance IDs contain
	// '&' (e.g. 6&2c0f7b2&0&1), so those are ignored.
	if len(parts) >= 3 {
		s := strings.TrimSpace(parts[len(parts)-1])
		if j := strings.LastIndex(s, "&"); j > 0 && len(s)-j <= 3 {
			s = s[:j] // strip the "&0" instance suffix
		}
		if s != "" && !strings.Contains(s, "&") && !strings.HasPrefix(s, "{") {
			d.serial = s
		}
	}
	return d
}

func (d device) name() string {
	return strings.TrimSpace(d.vendor + " " + d.product)
}

func (d device) serialText() string { return serialSuffix(d.serial) }

func (d device) key(fallback string) string {
	if d.serial != "" {
		return strings.ToLower(d.serial)
	}
	if n := d.name(); n != "" {
		return strings.ToLower(n)
	}
	return strings.ToLower(fallback)
}

// psFlag is a PowerShell parameter and the value after it.
var psFlag = regexp.MustCompile(`(?:^|\s)[-/]([A-Za-z]+)\s+("?)([A-Za-z0-9+/=]{8,})`)

// decodePowerShell returns the command hidden in a PowerShell
// -EncodedCommand argument (base64 of UTF-16LE text), or "".
func decodePowerShell(cmd string) string {
	l := strings.ToLower(cmd)
	if !strings.Contains(l, "powershell") && !strings.Contains(l, "pwsh") {
		return ""
	}
	// PowerShell accepts any prefix of -EncodedCommand (-e, -enc, …) and -ec.
	val := ""
	for _, m := range psFlag.FindAllStringSubmatch(cmd, -1) {
		f := strings.ToLower(m[1])
		if f == "ec" || strings.HasPrefix("encodedcommand", f) {
			val = m[3]
			break
		}
	}
	if val == "" {
		return ""
	}
	b, err := base64.StdEncoding.DecodeString(val)
	if err != nil || len(b) < 2 || len(b)%2 != 0 {
		return ""
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	out := strings.TrimSpace(string(utf16.Decode(u)))
	if len(out) > 2000 {
		out = out[:2000] + " …"
	}
	return out
}

// scriptName names a script block for people: its file, or for a script
// typed or generated in memory, what it is or its first real line.
func scriptName(text, path string) string {
	if path != "" {
		base := path
		if i := strings.LastIndexAny(base, `\/`); i >= 0 {
			base = base[i+1:]
		}
		return fmt.Sprintf("the script %s (%s)", base, path)
	}
	if m := cimClass.FindStringSubmatch(text); m != nil {
		return "the PowerShell commands Windows generates for " + m[1]
	}
	if l := firstLine(text); l != "" {
		return "a PowerShell script typed or run from memory (" + clip(l, 80) + ")"
	}
	return "a PowerShell script"
}

// cimClass finds the WMI class a generated (CDXML) module wraps.
var cimClass = regexp.MustCompile(`(?i)\$script:ClassName\s*=\s*'([^']+)'`)

// WindowsModule reports script blocks Windows itself provides: modules it
// generates from CDXML for its own WMI classes (Defender, networking,
// storage …), and modules installed with Windows.
func WindowsModule(text, path string) bool {
	if strings.Contains(text, "Microsoft.PowerShell.Cmdletization") {
		if m := cimClass.FindStringSubmatch(text); m != nil {
			c := strings.ToLower(strings.ReplaceAll(m[1], "/", `\`))
			if strings.HasPrefix(c, `root\microsoft\`) || strings.HasPrefix(c, `root\standardcimv2`) || strings.HasPrefix(c, `root\cimv2`) {
				return true
			}
		}
	}
	p := strings.ToLower(path)
	return strings.Contains(p, `\windows\system32\windowspowershell\v1.0\modules\`) ||
		strings.Contains(p, `\windows\syswow64\windowspowershell\v1.0\modules\`)
}

// psSuspicious are words that make PowerShell log a script block as a
// warning (from its own list), with what they are used for.
var psSuspicious = []struct{ word, what string }{
	{"VirtualAlloc", "memory allocation in another process"}, {"WriteProcessMemory", "writing into another process"},
	{"CreateRemoteThread", "starting code in another process"}, {"GetDelegateForFunctionPointer", "calling raw Windows functions"},
	{"MiniDumpWriteDump", "dumping a process's memory"}, {"ReadProcessMemory", "reading another process's memory"},
	{"AdjustTokenPrivileges", "changing its privileges"}, {"ImpersonateLoggedOnUser", "acting as another user"},
	{"DuplicateTokenEx", "copying a logon token"}, {"GetAsyncKeyState", "reading keystrokes"},
	{"DllImport", "calling Windows functions directly"}, {"Add-Type", "compiling code (Add-Type)"},
	{"FromBase64String", "decoding hidden (base64) data"}, {"EncodedCommand", "an encoded command"},
	{"DefineDynamicAssembly", "building code in memory"}, {"InteropServices", "calling Windows functions directly"},
	{"NonPublic", "reaching into hidden parts of .NET (reflection)"}, {"GetField", "reflection"},
	{"GetMethod", "reflection"}, {"InvokeMember", "reflection"}, {"Marshal", "raw memory access"},
	{"CryptoStream", "encryption"}, {"Bypass", "bypassing a restriction"},
}

// suspiciousWord finds which of PowerShell's warning words a script uses,
// and the line it is on.
func suspiciousWord(text string) (string, string) {
	lower := strings.ToLower(text)
	for _, s := range psSuspicious {
		re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(s.word) + `\b`)
		if loc := re.FindStringIndex(text); loc != nil {
			start := strings.LastIndex(lower[:loc[0]], "\n") + 1
			end := strings.Index(text[loc[0]:], "\n")
			if end < 0 {
				end = len(text) - loc[0]
			}
			return s.word + " (" + s.what + ")", strings.TrimSpace(text[start : loc[0]+end])
		}
	}
	return "", ""
}
