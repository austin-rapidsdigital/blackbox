package check

import (
	"strings"
	"testing"

	"github.com/casea1/blackbox/internal/winevt"
)

const auditpolCSV = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\r\n" +
	"WS-07,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,\r\n" +
	"WS-07,System,Removable Storage,{0CCE9245-69AE-11D9-BED3-505054503030},No Auditing,\r\n" +
	"WS-07,System,Account Lockout,{0CCE9217-69AE-11D9-BED3-505054503030},Success,\r\n"

func TestAuditpol(t *testing.T) {
	have, err := ParseAuditpol(auditpolCSV)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Result{}
	for _, r := range EvaluateAuditpol(have) {
		byName[r.Item] = r
	}
	if byName["Logon"].Status != Pass {
		t.Error("Logon should pass")
	}
	rs := byName["Removable Storage"]
	if rs.Status != Fail || !strings.Contains(rs.Fix, "/success:enable /failure:enable") || !strings.Contains(rs.Affects, "USB") {
		t.Errorf("Removable Storage: %+v", rs)
	}
	if al := byName["Account Lockout"]; al.Status != Fail || strings.Contains(al.Fix, "/success") {
		t.Errorf("Account Lockout needs failure only: %+v", al)
	}
}

func TestRegistryAndLogs(t *testing.T) {
	rs := EvaluateRegistry(func(key, value string) (string, error) {
		return "\r\nHKEY_LOCAL_MACHINE\\...\r\n    " + value + "    REG_DWORD    0x1\r\n", nil
	})
	for _, r := range rs {
		if r.Status != Pass {
			t.Errorf("%s: %s", r.Item, r.Status)
		}
	}
	logs := EvaluateLogs(func(name string) (winevt.LogSettings, error) {
		return winevt.ParseLogSettings("name: " + name + "\nenabled: false\nlogging:\n  retention: false\n  maxSize: 20971520\n"), nil
	})
	var sec, part Result
	for _, r := range logs {
		switch r.Item {
		case "Security log":
			sec = r
		case "Microsoft-Windows-Partition/Diagnostic":
			part = r
		}
	}
	if sec.Status != Fail || !strings.Contains(sec.Have, "20 MB") {
		t.Errorf("20 MB Security log should fail: %+v", sec)
	}
	if part.Status != Fail {
		t.Errorf("disabled Partition/Diagnostic log should fail: %+v", part)
	}
}

func TestLinuxAuditRules(t *testing.T) {
	// The recommended rules, as auditctl -l would list them, pass every check.
	var loaded []string
	for _, l := range strings.Split(AuditRules, "\n") {
		if strings.HasPrefix(l, "-a") || strings.HasPrefix(l, "-w") {
			loaded = append(loaded, l)
		}
	}
	for _, r := range EvaluateAuditRules(strings.Join(loaded, "\n"), "enabled 2\nbacklog_limit 8192\nlost 0\n") {
		if r.Status != Pass {
			t.Errorf("%s: %s (%s)", r.Item, r.Status, r.Have)
		}
	}
	// No rules at all: required items fail and point at the fix.
	var fails int
	for _, r := range EvaluateAuditRules("No rules", "enabled 1\nbacklog_limit 64\n") {
		if r.Status == Fail {
			fails++
			if r.Fix == "" {
				t.Errorf("%s: no fix given", r.Item)
			}
		}
	}
	if fails < 8 {
		t.Errorf("only %d failures with no rules loaded", fails)
	}
	if r := EvaluateCmdline("BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro audit=1 quiet"); r.Status != Pass {
		t.Error("audit=1 not detected")
	}
	if r := EvaluateCmdline("BOOT_IMAGE=/vmlinuz audit=0"); r.Status != Fail {
		t.Error("audit=0 should fail")
	}
	conf := ParseAuditdConf("log_format = RAW\nmax_log_file = 8\nnum_logs = 5\nmax_log_file_action = ROTATE\n")
	rs := EvaluateAuditdConf(conf)
	if rs[0].Status != Warn || !strings.Contains(rs[1].Have, "40 MB") {
		t.Errorf("auditd.conf evaluation wrong: %+v", rs)
	}
}

// usgLoaded is `auditctl -l` output in the form the DISA STIG for Ubuntu
// 24.04 (applied by Canonical USG) loads: its own key names, the mount
// program rather than the mount syscall, trailing slashes dropped.
var usgLoaded = strings.Join([]string{
	"-w /etc/passwd -p wa -k usergroup_modification",
	"-w /etc/group -p wa -k usergroup_modification",
	"-w /etc/shadow -p wa -k usergroup_modification",
	"-w /etc/gshadow -p wa -k usergroup_modification",
	"-w /etc/security/opasswd -p wa -k usergroup_modification",
	"-w /etc/sudoers -p wa -k privilege_modification",
	"-w /etc/sudoers.d -p wa -k privilege_modification",
	"-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv",
	"-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv",
	"-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv",
	"-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv",
	"-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng",
	"-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng",
	"-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng",
	"-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng",
	"-a always,exit -S all -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount",
	"-w /var/log/lastlog -p wa -k logins",
}, "\n")

func TestSTIGHardenedRulesPass(t *testing.T) {
	for _, r := range EvaluateAuditRules(usgLoaded, "enabled 2\nbacklog_limit 8192\n") {
		if r.Status == Fail {
			t.Errorf("a STIG-hardened system fails %q", r.Item)
		}
	}
}

func TestWatchMatchingIsExact(t *testing.T) {
	// /etc/sudoers.d alone must not count as watching /etc/sudoers.
	if watches("/etc/sudoers")([]string{"-w /etc/sudoers.d -p wa -k x"}) {
		t.Error("/etc/sudoers.d matched /etc/sudoers")
	}
	// auditctl lists "-w /etc/audit/" without the slash.
	if !watches("/etc/audit/")([]string{"-w /etc/audit -p wa -k auditconfig"}) {
		t.Error("/etc/audit without the trailing slash not recognised")
	}
}

func TestLockedRulesSayReboot(t *testing.T) {
	for _, r := range EvaluateAuditRules("No rules", "enabled 2\nbacklog_limit 8192\n") {
		if r.Status == Fail && !strings.Contains(r.Fix, "reboot") {
			t.Errorf("%s: fix %q should say a reboot is needed while rules are locked", r.Item, r.Fix)
		}
	}
}

func TestMissingRulesAddsOnlyGaps(t *testing.T) {
	exists := func(p string) bool { return p != "/var/run/faillock" }
	missing := MissingRules(AuditRules, usgLoaded, exists)
	joined := strings.Join(missing, "\n")
	// Already loaded under the STIG's own keys: not added again.
	for _, dup := range []string{"-w /etc/passwd ", "-w /etc/sudoers ", "-w /etc/sudoers.d/", "uid!=euid", "init_module", "-w /var/log/lastlog"} {
		if strings.Contains(joined, dup) {
			t.Errorf("rule already loaded would be added again: %s", dup)
		}
	}
	// Not loaded: added.
	for _, want := range []string{"-S mount,umount2", "clock_settime", "-w /etc/audit/", "-k root_commands", "-k log_tamper"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing rule not added: %s\n%s", want, joined)
		}
	}
	// A watch on a path that does not exist would stop the rules loading.
	if strings.Contains(joined, "/var/run/faillock") {
		t.Error("watch on a missing path added")
	}
	// Nothing is missing once everything is loaded.
	if again := MissingRules(AuditRules, AuditRules, nil); len(again) != 0 {
		t.Errorf("rules missing from themselves: %v", again)
	}
}
