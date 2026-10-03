package report

import (
	"os"

	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/collect"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// U6: an SSH spray of names that don't exist, recorded by PAM as wrong
// passwords and by sshd as unknown names: the names are kept, the reason
// says they don't exist, and "One source tried several accounts" fires.
func TestUnknownUserSpray(t *testing.T) {
	var lines []string
	for i, name := range []string{"admin", "oracle", "test", "ubuntu"} {
		pid := 7000 + i
		at := 1790730000 + i*3
		lines = append(lines,
			strings.NewReplacer("{at}", itoa(at), "{pid}", itoa(pid), "{name}", name, "{ser}", itoa(100+2*i)).Replace(
				`type=USER_AUTH msg=audit({at}.000:{ser}): pid={pid} uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=? acct="{name}" exe="/usr/lib/openssh/sshd-session" hostname=::1 addr=::1 terminal=ssh res=failed'`),
			strings.NewReplacer("{at}", itoa(at), "{pid}", itoa(pid), "{ser}", itoa(101+2*i)).Replace(
				`type=USER_LOGIN msg=audit({at}.040:{ser}): pid={pid} uid=0 auid=4294967295 ses=4294967295 msg='op=login acct=28696E76616C6964207573657229 exe="/usr/lib/openssh/sshd-session" hostname=? addr=::1 terminal=ssh res=failed'`))
	}
	evs := linuxEvents(t, lines)
	r := Build(evs, nil, Options{Location: time.UTC, WindowEnd: time.Unix(1790730000, 0).Add(time.Hour)})
	n := 0
	for _, e := range r.Events {
		if e.Action != "logon_failed" {
			continue
		}
		n++
		if strings.Contains(e.Summary, "wrong password") || strings.Contains(e.Summary, "(unknown user name)") {
			t.Errorf("row: %s", e.Summary)
		}
	}
	if n != 4 {
		t.Errorf("%d failed-logon rows, want 4 (one per attempt)", n)
	}
	if !hasFinding(r, "One source tried several accounts") {
		t.Errorf("findings: %v", findingTitles(r))
	}
}

// L3: a collection that found auditd stopped makes the system red in the
// report, with the reason.
func TestAuditOffAtCollection(t *testing.T) {
	end := fx0.Add(24 * time.Hour)
	runs := []*store.Run{
		{Time: fx0.Add(time.Hour), Host: "ubu1", OS: "linux"},
		{Time: fx0.Add(2 * time.Hour), Host: "ubu1", OS: "linux", AuditOff: "the audit service (auditd) is not running (systemctl is-active auditd: inactive)"},
	}
	r := Build([]*event.Event{{Time: fx0, Host: "ubu1", OS: "linux", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "x"}}, runs,
		Options{WindowEnd: end, Location: time.UTC, Systems: []SystemInfo{{Name: "ubu1", OS: "linux", LastRun: fx0.Add(2 * time.Hour)}}})
	if len(r.SystemRows) != 1 || r.SystemRows[0].AuditOff == "" || !strings.Contains(r.SystemRows[0].StatusMsg, "Auditing was off") {
		t.Fatalf("system: %+v", r.SystemRows)
	}
	if len(r.Health.AuditOff) != 1 {
		t.Errorf("health: %v", r.Health.AuditOff)
	}
	// Running again at the next collection: not red.
	runs = append(runs, &store.Run{Time: fx0.Add(3 * time.Hour), Host: "ubu1", OS: "linux"})
	r = Build(nil, runs, Options{WindowEnd: end, Location: time.UTC, Systems: []SystemInfo{{Name: "ubu1", OS: "linux", LastRun: fx0.Add(3 * time.Hour)}}})
	if r.SystemRows[0].AuditOff != "" {
		t.Errorf("still off: %+v", r.SystemRows[0])
	}
}

// linuxEvents translates audit log lines as a collection would.
func linuxEvents(t *testing.T, lines []string) []*event.Event {
	t.Helper()
	f := t.TempDir() + "/audit.log"
	if err := os.WriteFile(f, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	evs, _, err := collect.LinuxFiles([]string{f}, nil, "ubu1", "", time.Unix(1790740000, 0))
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// U6: sshd allows several password tries per connection; every try for a
// name that doesn't exist says so, not just the last one.
func TestUnknownUserEveryTry(t *testing.T) {
	auth := `type=USER_AUTH msg=audit({at}.000:{ser}): pid=7000 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=? acct="admin" exe="/usr/sbin/sshd" hostname=10.1.1.9 addr=10.1.1.9 terminal=ssh res=failed'`
	login := `type=USER_LOGIN msg=audit(1790730006.040:20): pid=7000 uid=0 auid=4294967295 ses=4294967295 msg='op=login acct=28696E76616C6964207573657229 exe="/usr/sbin/sshd" hostname=? addr=10.1.1.9 terminal=ssh res=failed'`
	var lines []string
	for i := 0; i < 3; i++ {
		lines = append(lines, strings.NewReplacer("{at}", itoa(1790730000+3*i), "{ser}", itoa(10+i)).Replace(auth))
	}
	evs := linuxEvents(t, append(lines, login))
	r := Build(evs, nil, Options{Location: time.UTC, WindowEnd: time.Unix(1790730000, 0).Add(time.Hour)})
	n := 0
	for _, e := range r.Events {
		if e.Action == "logon_failed" {
			n++
			if !strings.HasSuffix(e.Summary, "the user name does not exist.") {
				t.Errorf("row: %s", e.Summary)
			}
		}
	}
	if n != 3 {
		t.Errorf("%d rows, want 3", n)
	}
}
