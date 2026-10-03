package linuxlog

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/casea1/blackbox/internal/event"
)

// translateLines runs audit log lines through a translator.
func translateLines(t *testing.T, users Users, lines ...string) []*event.Event {
	t.Helper()
	tr := NewTranslator("ws12", users)
	var out []*event.Event
	if _, err := ParseAuditStream(strings.NewReader(strings.Join(lines, "\n")+"\n"), func(ev *Event) error {
		if e := tr.Audit(ev); e != nil {
			out = append(out, e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// execRec is an execve record of cmd run as root by auid in session ses.
func execRec(serial int, sec int, auid, ses int, cmd string) []string {
	exe := strings.Fields(strings.TrimPrefix(cmd, "-"))[0]
	if !strings.HasPrefix(exe, "/") {
		exe = "/usr/bin/" + exe
	}
	at := fmt.Sprintf("1790730%03d.000:%d", sec, serial)
	return []string{
		fmt.Sprintf(`type=SYSCALL msg=audit(%s): arch=c000003e syscall=59 success=yes exit=0 items=2 ppid=100 pid=%d auid=%d uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=%d comm="x" exe=%q key="root_commands"`, at, 5000+serial, auid, ses, exe),
		fmt.Sprintf(`type=PROCTITLE msg=audit(%s): proctitle=%s`, at, strings.ToUpper(hex.EncodeToString([]byte(strings.ReplaceAll(cmd, " ", "\x00"))))),
		fmt.Sprintf(`type=EOE msg=audit(%s):`, at),
	}
}

func summaries(evs []*event.Event) string {
	var s []string
	for _, e := range evs {
		s = append(s, e.Action+": "+e.Summary)
	}
	return strings.Join(s, "\n")
}

// U7: with the rules locked (-e 2) the kernel refuses "auditctl -e 0" and
// "auditctl -D" and records res=0. That is an attempt; auditing stayed on.
func TestRefusedAuditChangeIsAnAttempt(t *testing.T) {
	evs := translateLines(t, Users{1001: "jsmith"},
		`type=CONFIG_CHANGE msg=audit(1790730000.000:10): op=set audit_enabled=0 old=2 auid=1001 ses=3 subj=unconfined res=0`,
		`type=CONFIG_CHANGE msg=audit(1790730001.000:11): auid=1001 ses=3 subj=unconfined op=remove_rule key="identity" list=4 res=0`,
		`type=CONFIG_CHANGE msg=audit(1790730002.000:12): auid=1001 ses=3 op=remove_rule audit_enabled=2 res=0`,
	)
	if len(evs) != 3 {
		t.Fatalf("got %d events:\n%s", len(evs), summaries(evs))
	}
	for _, e := range evs {
		if e.Action != "audit_rules_refused" || e.Outcome != "failure" {
			t.Errorf("refused change reported as %s: %s", e.Action, e.Summary)
		}
		if strings.Contains(e.Summary, "OFF") || strings.Contains(e.Summary, "locked the audit rules") {
			t.Errorf("refused change reads as done: %s", e.Summary)
		}
	}
	if evs[0].Severity != event.SevHigh || !strings.Contains(evs[0].Summary, "jsmith tried to turn off auditing; refused because the audit rules are locked") {
		t.Errorf("-e 0 refused: %s %s", evs[0].Severity, evs[0].Summary)
	}
	if evs[1].Severity != event.SevMedium || !strings.Contains(evs[1].Summary, "tried to remove audit rules") {
		t.Errorf("-D refused: %s %s", evs[1].Severity, evs[1].Summary)
	}
	// Done (res=1): auditing really is off.
	evs = translateLines(t, Users{1001: "jsmith"},
		`type=CONFIG_CHANGE msg=audit(1790730000.000:10): op=set audit_enabled=0 old=1 auid=1001 ses=3 subj=unconfined res=1`)
	if len(evs) != 1 || evs[0].Action != "audit_disabled" {
		t.Errorf("accepted -e 0: %s", summaries(evs))
	}
}

// U8: systemd stops auditd, so its record names no one; the person is
// whoever ran "systemctl stop auditd" just before.
func TestAuditdStopNamesWhoStoppedIt(t *testing.T) {
	cmd := `type=USER_CMD msg=audit(1790730000.000:20): pid=6000 uid=1001 auid=1001 ses=3 msg='cwd="/home/jsmith" cmd=73797374656D63746C2073746F70206175646974640A exe="/usr/bin/sudo" terminal=pts/0 res=success'`
	cmd = strings.Replace(cmd, "73797374656D63746C2073746F70206175646974640A", strings.ToUpper(hex.EncodeToString([]byte("systemctl stop auditd"))), 1)
	end := `type=DAEMON_END msg=audit(1790730003.000:21): op=terminate auid=4294967295 uid=0 ses=4294967295 pid=1 subj=unconfined res=success`
	evs := translateLines(t, Users{1001: "jsmith"}, cmd, end)
	var stop *event.Event
	for _, e := range evs {
		if e.Action == "audit_stopped" {
			stop = e
		}
	}
	if stop == nil || stop.User != "jsmith" || stop.Severity != event.SevHigh || !strings.Contains(stop.Summary, "stopped by jsmith (systemctl stop auditd)") {
		t.Fatalf("stop not attributed:\n%s", summaries(evs))
	}
	evs = translateLines(t, nil, end)
	if len(evs) != 1 || evs[0].User != "" || evs[0].Severity != event.SevLow {
		t.Errorf("unattributed stop: %s", summaries(evs))
	}
}

// U5 and U6: OpenSSH 10 records the password check in sshd-session and the
// failed logon in sshd; sshd says only "(invalid user)", the password check
// has the name that was tried.
func TestOpenSSH10FailedLogonMerges(t *testing.T) {
	evs := translateLines(t, nil,
		`type=USER_AUTH msg=audit(1790730000.000:30): pid=7000 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=? acct="admin" exe="/usr/lib/openssh/sshd-session" hostname=::1 addr=::1 terminal=ssh res=failed'`,
		`type=USER_LOGIN msg=audit(1790730000.040:31): pid=7000 uid=0 auid=4294967295 ses=4294967295 msg='op=login acct=28696E76616C6964207573657229 exe="/usr/sbin/sshd" hostname=? addr=::1 terminal=ssh res=failed'`,
	)
	if len(evs) != 2 {
		t.Fatalf("got:\n%s", summaries(evs))
	}
	if evs[0].DedupeKey != evs[1].DedupeKey {
		t.Errorf("records of one attempt don't merge: %q vs %q", evs[0].DedupeKey, evs[1].DedupeKey)
	}
	if evs[1].Target != "admin" || !strings.Contains(evs[1].Summary, "Failed logon for admin via SSH from localhost — the user name does not exist.") {
		t.Errorf("unknown user: %s", evs[1].Summary)
	}
	if program("/usr/lib/openssh/sshd-auth") != "sshd" {
		t.Error("sshd-auth not named sshd")
	}
}

// U11: memory, system, network and bind mounts are not removable disks.
func TestMountKind(t *testing.T) {
	cases := map[string]string{
		"mount /dev/sdb1 /mnt/usb":                     "disk",
		"mount -t vfat /dev/sdc1 /media/stick":         "disk",
		"mount UUID=1234-ABCD /mnt/x":                  "disk",
		"mount /mnt/usb":                               "disk",
		"mount -t tmpfs tmpfs /mnt/ram":                "",
		"mount -t proc proc /mnt/proc":                 "",
		"mount -ttmpfs none /mnt/t":                    "",
		"mount --bind /srv/data /mnt/data":             "",
		"mount -o bind,ro /srv /mnt/srv":               "",
		"mount -t overlay overlay -o lowerdir=/a /mnt": "",
		"mount -t nfs fs1:/export /mnt/nfs":            "network",
		"mount -t cifs //fs1/share /mnt/share":         "network",
		"mount fs1:/export /mnt/nfs":                   "network",
		"mount -o remount,rw /":                        "",
	}
	for cmd, want := range cases {
		if got := mountKind(cmd); got != want {
			t.Errorf("mountKind(%q) = %q, want %q", cmd, got, want)
		}
	}
}

// U4: the login message (pam_motd's run-parts /etc/update-motd.d) and a
// root login shell's profile scripts are one line, not dozens of "ran as
// root" rows; what the person types afterwards is still reported.
func TestLoginScriptsCollapse(t *testing.T) {
	var lines []string
	add := func(l []string) { lines = append(lines, l...) }
	add(execRec(1, 0, 1001, 5, "run-parts --lsbsysinit /etc/update-motd.d"))
	add(execRec(2, 0, 1001, 5, "/bin/sh /etc/update-motd.d/00-header"))
	add(execRec(3, 0, 1001, 5, "uname -o"))
	add(execRec(4, 1, 1001, 5, "landscape-sysinfo"))
	lines = append(lines, `type=USER_START msg=audit(1790730002.000:50): pid=7100 uid=0 auid=1001 ses=5 msg='op=PAM:session_open grantors=pam_unix acct="jsmith" exe="/usr/sbin/sshd" hostname=10.1.1.5 addr=10.1.1.5 terminal=ssh res=success'`)
	add(execRec(5, 10, 1001, 5, "id"))
	// sudo -i: a root login shell and its profile scripts.
	add(execRec(6, 20, 1001, 6, "-bash"))
	add(execRec(7, 20, 1001, 6, "locale-check C.UTF-8"))
	add(execRec(8, 20, 1001, 6, "cat /etc/debuginfod/ubuntu.urls"))
	add(execRec(9, 21, 1001, 6, "dircolors -b"))
	add(execRec(10, 22, 1001, 6, "cat /etc/shadow"))
	add(execRec(11, 40, 1001, 6, "locale-check C.UTF-8"))
	evs := translateLines(t, Users{1001: "jsmith"}, lines...)
	var got []string
	for _, e := range evs {
		if e.Action == "root_command" || e.Action == "login_scripts" {
			got = append(got, e.Action+": "+e.Command)
		}
	}
	want := []string{
		"login_scripts: run-parts --lsbsysinit /etc/update-motd.d",
		"root_command: id", // after the session started
		"login_scripts: -bash",
		"root_command: cat /etc/shadow",
		"root_command: locale-check C.UTF-8", // long after the shell started
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
