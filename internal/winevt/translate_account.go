// Account and group changes (472x, 473x, 475x).

package winevt

import (
	"fmt"
	"strings"

	"github.com/casea1/blackbox/internal/event"
)

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
	// Deleting an account also removes it from its primary group, "None"
	// (or "Domain Users"), RID 513. That says nothing new.
	if !added && strings.HasSuffix(r.Get("TargetSid"), "-513") {
		return nil
	}
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
