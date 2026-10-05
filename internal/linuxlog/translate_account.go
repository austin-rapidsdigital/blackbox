// Account and group changes (ADD_USER, USER_MGMT, USER_CHAUTHTOK, …),
// with the group a usermod command named.

package linuxlog

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

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

// groupFileWriter are the programs that create or delete a group (userdel
// deletes the user's own group). useradd is not one: its "added to group"
// records name real memberships (useradd -G).
var groupFileWriter = map[string]bool{"groupadd": true, "groupdel": true, "userdel": true}

// groupItselfOp is an operation on a group, not on a member of one:
// "adding group to /etc/gshadow", "delete-group", "removing group".
var groupItselfOp = regexp.MustCompile(`\b(add|adding|remov\w*|delet\w*)[- ](shadow )?group\b`)

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
		t.groupPID[pidKey] = g
		e.Action, e.Severity, e.Target = "group_deleted", event.SevMedium, g
		e.Summary = fmt.Sprintf("%s deleted the group %s.", by, g)
	case groupItselfOp.MatchString(op) || (acct != "" && t.groupPID[pidKey] == acct && groupFileWriter[program(r.Get("exe"))]):
		// groupadd and groupdel (and userdel removing a user's own group)
		// record the group file being written as well: the group was
		// created or deleted, which has its own row; no one joined or
		// left a group (U14).
		return nil
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
