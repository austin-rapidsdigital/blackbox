package linuxlog

import (
	"fmt"
	"strings"
	"testing"

	"github.com/casea1/blackbox/internal/event"
)

// sysRec is a SYSCALL record by auid 1001 with one PATH item.
func sysRec(serial int, syscall, success, exit, a1, a2, exe, key, file string) []string {
	at := fmt.Sprintf("1790731%03d.000:%d", serial, serial)
	return []string{
		fmt.Sprintf(`type=SYSCALL msg=audit(%s): arch=c000003e syscall=%s success=%s exit=%s a0=ffffff9c a1=%s a2=%s items=1 ppid=1 pid=%d auid=1001 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=pts0 ses=3 comm=%q exe=%q key=%q`,
			at, syscall, success, exit, a1, a2, 7000+serial, base(exe), exe, key),
		fmt.Sprintf(`type=PATH msg=audit(%s): item=0 name=%q inode=12 dev=08:01 mode=0100755 ouid=0 ogid=0 nametype=NORMAL`, at, file),
		fmt.Sprintf(`type=EOE msg=audit(%s):`, at),
	}
}

// A3, U10, A5: refused access, permission changes, setuid, deletions,
// persistence and logon files, Blackbox's own files, and any other rule.
func TestFileActivity(t *testing.T) {
	cases := []struct {
		lines  []string
		action string
		sev    event.Severity
		text   string
	}{
		{sysRec(1, "257", "no", "-13", "0", "0", "/usr/bin/cat", "perm_access", "/etc/shadow"), "file_access_denied", event.SevMedium, "jsmith was refused access to /etc/shadow (using cat)"},
		{sysRec(2, "257", "no", "-2", "0", "0", "/usr/bin/cat", "perm_access", "/nope"), "", "", ""}, // ENOENT: not a refusal
		{sysRec(3, "268", "yes", "0", "7ffd", "9ed", "/usr/bin/chmod", "perm_mod", "/usr/local/bin/tool"), "setuid_set", event.SevHigh, "setuid"},
		{sysRec(4, "268", "yes", "0", "7ffd", "1a4", "/usr/bin/chmod", "perm_mod", "/home/jsmith/notes"), "permissions_changed", event.SevLow, "to 0644"},
		{sysRec(5, "90", "yes", "0", "1ed", "0", "/usr/bin/chmod", "perm_mod", "/etc/hosts"), "permissions_changed", event.SevMedium, "/etc/hosts"},
		{sysRec(6, "260", "yes", "0", "7ffd", "0", "/usr/bin/chown", "perm_mod", "/etc/cron.d/job"), "scheduled_job_changed", event.SevMedium, "scheduled jobs"},
		{sysRec(7, "263", "yes", "0", "7ffd", "0", "/usr/bin/rm", "delete", "/home/jsmith/a.txt"), "file_deleted", event.SevLow, "deleted or renamed"},
		{sysRec(8, "257", "yes", "3", "7ffd", "241", "/usr/bin/vi", "logon_config", "/etc/pam.d/sshd"), "logon_config_changed", event.SevHigh, "logon rules (PAM)"},
		{sysRec(9, "257", "yes", "3", "7ffd", "241", "/usr/bin/vi", "logon_config", "/etc/ssh/sshd_config"), "logon_config_changed", event.SevMedium, "SSH server"},
		{sysRec(10, "257", "yes", "3", "7ffd", "241", "/usr/bin/vi", "systemd_units", "/etc/systemd/system/backdoor.service"), "service_unit_changed", event.SevMedium, "services and timers"},
		{sysRec(11, "257", "yes", "3", "7ffd", "241", "/usr/bin/nano", "blackbox", "/etc/blackbox/blackbox.conf"), "blackbox_config_changed", event.SevHigh, "Blackbox's settings"},
		{sysRec(12, "257", "yes", "3", "7ffd", "241", "/usr/local/bin/blackbox", "blackbox", "/etc/blackbox/blackbox.conf"), "blackbox_config_changed", event.SevMedium, "with Blackbox itself"},
		{sysRec(13, "257", "yes", "3", "7ffd", "241", "/usr/bin/dpkg", "systemd_units", "/usr/lib/systemd/system/foo.service"), "", "", ""}, // package update
		{sysRec(14, "257", "yes", "3", "7ffd", "241", "/usr/bin/vi", "my_site_rule", "/srv/secret/plan.txt"), "audit_rule", event.SevInfo, `the audit rule "my_site_rule"`},
	}
	for _, c := range cases {
		evs := translateLines(t, Users{1001: "jsmith"}, c.lines...)
		if c.action == "" {
			if len(evs) != 0 {
				t.Errorf("%s: want nothing, got %s", c.lines[0][:40], summaries(evs))
			}
			continue
		}
		if len(evs) != 1 || evs[0].Action != c.action || evs[0].Severity != c.sev || !strings.Contains(evs[0].Summary, c.text) {
			t.Errorf("want %s %s %q, got:\n%s", c.action, c.sev, c.text, summaries(evs))
		}
	}
}

// A5, U9: commands that change Blackbox itself.
func TestBlackboxCommands(t *testing.T) {
	cases := map[string]string{
		"blackbox config set exclude_users bob":                     "blackbox_config_changed high",
		"/usr/local/bin/blackbox config set site_name Lab":          "blackbox_config_changed medium",
		"systemctl stop blackbox.timer":                             "blackbox_stopped high",
		"systemctl disable --now blackbox.timer":                    "blackbox_stopped high",
		"blackbox uninstall":                                        "blackbox_uninstalled high",
		`schtasks /Change /TN "Blackbox Audit Collection" /Disable`: "blackbox_stopped high",
		"rm -rf /var/lib/blackbox/spool":                            "blackbox_files_removed high",
		"blackbox status":                                           "",
		"systemctl status blackbox.timer":                           "",
	}
	for cmd, want := range cases {
		action, sev, _, ok := event.BlackboxChange(cmd)
		got := ""
		if ok {
			got = action + " " + string(sev)
		}
		if got != want {
			t.Errorf("%q: %q, want %q", cmd, got, want)
		}
	}
	// Through sudo.
	line := fmt.Sprintf(`type=USER_CMD msg=audit(1790730000.000:20): pid=6000 uid=1001 auid=1001 ses=3 msg='cwd="/home/jsmith" cmd=%s exe="/usr/bin/sudo" terminal=pts/0 res=success'`,
		strings.ToUpper(fmt.Sprintf("%x", "blackbox config set retention_days 30")))
	evs := translateLines(t, Users{1001: "jsmith"}, line)
	if len(evs) != 1 || evs[0].Action != "blackbox_config_changed" || evs[0].Severity != event.SevHigh {
		t.Errorf("sudo config set: %s", summaries(evs))
	}
}
