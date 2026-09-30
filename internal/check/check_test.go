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
