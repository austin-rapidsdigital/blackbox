package winevt

import (
	"encoding/base64"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/casea1/blackbox/internal/event"
)

// loadSample translates testdata/sample-events.xml and returns the
// events keyed by "EventID@HH:MM:SS" (UTC). Skipped raw events map to nil.
func loadSample(t *testing.T) map[string]*event.Event {
	t.Helper()
	f, err := os.Open("../../testdata/sample-events.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tr := NewTranslator()
	out := map[string]*event.Event{}
	err = ParseStream(f, func(r *Raw) error {
		key := strconv.Itoa(r.EventID) + "@" + r.Time.Format("15:04:05")
		e := tr.Translate(r)
		if prev, ok := out[key]; ok && prev != nil && e == nil {
			return nil // keep the first translated event for duplicate keys
		}
		out[key] = e
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTranslateSample(t *testing.T) {
	ev := loadSample(t)
	cases := []struct {
		key      string
		cat      event.Category
		sev      event.Severity
		contains string
	}{
		{"4624@08:02:11", event.CatLogon, event.SevInfo, "jsmith logged on at the keyboard."},
		{"4624@09:15:30", event.CatLogon, event.SevInfo, "admin_jd logged on via Remote Desktop from 10.1.1.20 with administrator rights."},
		{"4672@09:15:30", event.CatPrivileged, event.SevLow, "admin_jd logged on via Remote Desktop from 10.1.1.20 with administrator privileges."},
		{"4625@10:02:01", event.CatFailedLogon, event.SevLow, "Failed logon for administrator over the network from 10.1.1.99 — wrong password."},
		{"4625@10:03:02", event.CatFailedLogon, event.SevLow, "the user name does not exist"},
		{"4625@10:03:10", event.CatFailedLogon, event.SevLow, "account is disabled"},
		{"4740@11:15:41", event.CatFailedLogon, event.SevMedium, "Account mjones was locked out"},
		{"4720@13:01:41", event.CatAccount, event.SevMedium, "admin_jd created the user account tempuser."},
		{"4732@13:02:05", event.CatAccount, event.SevHigh, "admin_jd added tempuser to the privileged group Administrators."},
		{"4688@13:01:40", event.CatPrivileged, event.SevLow, "admin_jd ran with administrator rights: net  user tempuser"},
		{"4688@16:38:00", event.CatPrivileged, event.SevHigh, "can clear logs or weaken auditing"},
		{"4719@13:20:00", event.CatIntegrity, event.SevHigh, `Audit policy for "Removable Storage" was changed by admin_jd`},
		{"4616@13:25:30", event.CatIntegrity, event.SevMedium, "moving the clock 2.0 hours back"},
		{"1102@16:40:00", event.CatIntegrity, event.SevHigh, "The Security log was cleared by admin_jd."},
		{"104@16:38:00", event.CatIntegrity, event.SevHigh, "The Application log was cleared by admin_jd."},
		{"4648@15:40:12", event.CatPrivileged, event.SevMedium, "jsmith used the credentials of admin_jd (RunAs"},
		{"4698@13:10:00", event.CatOther, event.SevMedium, `Scheduled task \Updater was created by admin_jd.`},
		{"7045@13:12:00", event.CatOther, event.SevMedium, "UpdaterSvc"},
		{"1006@08:30:03", event.CatRemovable, event.SevMedium, "USB storage connected: SanDisk Cruzer Blade (serial 4C530001231109115405), 15.6 GB."},
		{"1006@08:55:40", event.CatRemovable, event.SevInfo, "Removable storage disconnected: SanDisk Cruzer Blade"},
		{"1006@16:50:00", event.CatRemovable, event.SevMedium, "virtual disk (ISO/VHD file) was mounted"},
		{"6416@08:30:02", event.CatRemovable, event.SevMedium, "Removable device connected: SanDisk Cruzer Blade (serial 4C530001231109115405)."},
		{"400@08:30:01", event.CatRemovable, event.SevMedium, "SanDisk Cruzer Blade"},
		{"4663@08:41:15", event.CatRemovable, event.SevMedium, `jsmith wrote to removable media: \Device\HarddiskVolume7\Projects\budget-2027.xlsx (using EXCEL.EXE).`},
		{"4656@16:56:00", event.CatRemovable, event.SevMedium, "jsmith was blocked from accessing removable media"},
		{"1116@08:42:05", event.CatOther, event.SevHigh, `HackTool:Win32/Keygen in E:\tools\keygen.exe`},
		{"5001@16:58:00", event.CatOther, event.SevHigh, "real-time protection was turned off"},
		{"1074@17:06:00", event.CatIntegrity, event.SevInfo, "admin_jd initiated a restart using shutdown.exe — Other (Planned)."},
		{"6008@07:52:40", event.CatIntegrity, event.SevLow, "shut down unexpectedly"},
	}
	for _, c := range cases {
		e := ev[c.key]
		if e == nil {
			t.Errorf("%s: not translated", c.key)
			continue
		}
		if e.Category != c.cat || e.Severity != c.sev {
			t.Errorf("%s: got %s/%s, want %s/%s", c.key, e.Category, e.Severity, c.cat, c.sev)
		}
		if !strings.Contains(e.Summary, c.contains) {
			t.Errorf("%s: summary %q does not contain %q", c.key, e.Summary, c.contains)
		}
		if e.Host != "WS-07" || e.OS != "windows" || e.Time.IsZero() {
			t.Errorf("%s: missing host/os/time: %+v", c.key, e)
		}
	}

	// Routine noise must be dropped.
	for _, key := range []string{
		"4624@07:58:05", // SYSTEM service logon
		"4672@07:58:05", // SYSTEM special privileges
		"4616@07:59:10", // Windows Time service clock sync
		"4688@08:03:00", // non-elevated notepad
		"5156@08:10:00", // firewall connection noise
		"7036@07:58:30", // service state change
		"1006@07:58:03", // internal system disk
	} {
		if e, ok := ev[key]; !ok {
			t.Errorf("%s: missing from sample", key)
		} else if e != nil {
			t.Errorf("%s: should be dropped, got %q", key, e.Summary)
		}
	}
}

func TestParseStreamBareSequence(t *testing.T) {
	// wevtutil qe /f:xml emits events with no root element.
	in := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4740</EventID><TimeCreated SystemTime="2026-09-28T11:15:41.1Z"/><EventRecordID>7</EventRecordID><Channel>Security</Channel><Computer>ws-07.corp.local</Computer></System><EventData><Data Name="TargetUserName">mjones</Data></EventData></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="EventLog"/><EventID Qualifiers="32768">6008</EventID><TimeCreated SystemTime="2026-09-28T07:52:40Z"/><EventRecordID>8</EventRecordID><Channel>System</Channel><Computer>ws-07.corp.local</Computer></System><EventData><Data>7:52:10 AM</Data><Data>9/28/2026</Data></EventData></Event>`
	var got []*Raw
	if err := ParseStream(strings.NewReader(in), func(r *Raw) error { got = append(got, r); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2", len(got))
	}
	if got[0].EventID != 4740 || got[0].RecordID != 7 || got[0].Get("TargetUserName") != "mjones" {
		t.Errorf("event 0 parsed wrong: %+v", got[0])
	}
	if got[1].EventID != 6008 || got[1].Get("Data0") != "7:52:10 AM" || got[1].Get("Data1") != "9/28/2026" {
		t.Errorf("event 1 parsed wrong: %+v", got[1])
	}
	if shortHost(got[0].Computer) != "WS-07" {
		t.Errorf("shortHost = %q", shortHost(got[0].Computer))
	}
}

func TestParseDeviceID(t *testing.T) {
	cases := []struct {
		id, vendor, product, serial string
		storage                     bool
	}{
		{`USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\4C530001231109115405&0`, "SanDisk", "Cruzer Blade", "4C530001231109115405", true},
		{`USB\VID_0781&PID_5567\4C530001231109115405`, "", "", "4C530001231109115405", false},
		{`USB\VID_046D&PID_C52B\6&2c0f7b2&0&1`, "", "", "", false}, // generated instance ID, not a serial
		{`SWD\WPDBUSENUM\_??_USBSTOR#DISK&VEN_KINGSTON&PROD_DT&REV_PMAP#E0D55EA5&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`, "KINGSTON", "DT", "", true},
	}
	for _, c := range cases {
		d := parseDeviceID(c.id)
		if d.vendor != c.vendor || d.product != c.product || d.serial != c.serial || d.storage != c.storage {
			t.Errorf("parseDeviceID(%q) = %+v", c.id, d)
		}
	}
}

func TestFailureReason(t *testing.T) {
	cases := map[[2]string]string{
		{"0xC000006D", "0xC000006A"}: "wrong password",
		{"0xc000006d", "0xc0000064"}: "the user name does not exist",
		{"0xC0000234", "0x0"}:        "account is locked out",
		{"0xC000006D", ""}:           "bad user name or password",
		{"0xDEADBEEF", "0x0"}:        "error code 0xdeadbeef",
	}
	for in, want := range cases {
		if got := failureReason(in[0], in[1]); got != want {
			t.Errorf("failureReason(%q,%q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

func TestIsServiceAccount(t *testing.T) {
	tr := NewTranslator()
	yes := [][2]string{{"S-1-5-18", "WS-07$"}, {"S-1-5-19", "LOCAL SERVICE"}, {"S-1-5-90-0-1", "DWM-1"}, {"S-1-5-21-1-2-3-1000", "FILESRV$"}}
	for _, a := range yes {
		if !tr.isServiceAccount(a[0], a[1]) {
			t.Errorf("isServiceAccount(%v) = false", a)
		}
	}
	if tr.isServiceAccount("S-1-5-21-1-2-3-1001", "jsmith") {
		t.Error("jsmith treated as a service account")
	}
}

// sec builds a Security event for tests.
func sec(id int, data map[string]string) *Raw {
	return &Raw{Provider: "Microsoft-Windows-Security-Auditing", Channel: "Security", EventID: id,
		Computer: "WS-07", Time: time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC), Data: data}
}

func TestAdmToolkitCompatibility(t *testing.T) {
	tr := NewTranslator()
	user := map[string]string{"TargetUserSid": "S-1-5-21-1-2-3-1001", "TargetUserName": "jdoe.adm", "TargetDomainName": "WS-07"}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range user {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	// A session ended by an administrator (logoff.exe) or a time limit
	// produces 4634 only; a user-chosen logoff also produces 4647, which
	// wins the merge.
	ended := tr.Translate(sec(4634, with(map[string]string{"LogonType": "10", "TargetLogonId": "0x3E7A1"})))
	if ended == nil || !strings.Contains(ended.Summary, "session ended") || ended.DedupeKey != "logoff|0x3e7a1" {
		t.Errorf("4634: %+v", ended)
	}
	chosen := tr.Translate(sec(4647, with(map[string]string{"TargetLogonId": "0x3E7A1"})))
	if chosen == nil || chosen.DedupeKey != ended.DedupeKey || chosen.Priority <= ended.Priority {
		t.Errorf("4647 should merge with and win over 4634: %+v", chosen)
	}
	if tr.Translate(sec(4634, with(map[string]string{"LogonType": "3", "TargetLogonId": "0x1"}))) != nil {
		t.Error("network logoffs (type 3) are noise and must be skipped")
	}

	// A cached unlock (type 13) is an unlock, like type 7.
	if e := tr.Translate(sec(4624, with(map[string]string{"LogonType": "13", "TargetLogonId": "0x2"}))); e == nil || !e.Interactive {
		t.Errorf("type 13: %+v", e)
	}

	// An administrator's UAC logon pair is one logon.
	a := tr.Translate(sec(4624, with(map[string]string{"LogonType": "2", "TargetLogonId": "0x100", "TargetLinkedLogonId": "0x200", "ElevatedToken": "%%1842"})))
	b := tr.Translate(sec(4624, with(map[string]string{"LogonType": "2", "TargetLogonId": "0x200", "TargetLinkedLogonId": "0x100", "ElevatedToken": "%%1843"})))
	if a.DedupeKey == "" || a.DedupeKey != b.DedupeKey || a.Priority <= b.Priority {
		t.Errorf("linked logons: %q/%d and %q/%d", a.DedupeKey, a.Priority, b.DedupeKey, b.Priority)
	}

	// OpenSSH logons say SSH, not "clear-text password".
	ssh := tr.Translate(sec(4624, with(map[string]string{"LogonType": "8", "TargetLogonId": "0x3", "LogonProcessName": "sshd", "IpAddress": "10.1.1.5"})))
	if ssh == nil || !strings.Contains(ssh.Summary, "via SSH") || strings.Contains(ssh.Summary, "clear-text") {
		t.Errorf("sshd logon: %+v", ssh)
	}

	// Actions by the system itself are shown as SYSTEM, not the computer account.
	grp := tr.Translate(sec(4731, map[string]string{"SubjectUserSid": "S-1-5-18", "SubjectUserName": "WS-07$", "SubjectDomainName": "WORKGROUP",
		"TargetUserName": "Blackbox Senders", "TargetDomainName": "WS-07", "TargetSid": "S-1-5-21-1-2-3-1010"}))
	if grp == nil || !strings.HasPrefix(grp.Summary, "SYSTEM ") {
		t.Errorf("system action: %+v", grp)
	}

	// PowerShell -EncodedCommand (remote management) is decoded, checked
	// for tampering, and passwords in it are hidden.
	enc := base64.StdEncoding.EncodeToString(utf16le("$env:BLACKBOX_SHARE_PASSWORD='Qx7!Harbor-L26'; wevtutil cl Security"))
	p := tr.Translate(sec(4688, map[string]string{"SubjectUserSid": "S-1-5-21-1-2-3-1001", "SubjectUserName": "jdoe.adm", "SubjectDomainName": "WS-07",
		"NewProcessName": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "TokenElevationType": "%%1937",
		"CommandLine": "powershell.exe -NoProfile -EncodedCommand " + enc, "ParentProcessName": `C:\Windows\System32\wsmprovhost.exe`}))
	if p == nil || p.Action != "audit_tamper_command" || !strings.Contains(p.Summary, "wevtutil cl Security") {
		t.Fatalf("encoded command: %+v", p)
	}
	all := p.Summary
	for _, d := range p.Details {
		all += " " + d.Value
	}
	if strings.Contains(all, "Qx7!Harbor-L26") {
		t.Errorf("password shown in the report: %s", all)
	}
}

func utf16le(s string) []byte {
	var b []byte
	for _, r := range utf16.Encode([]rune(s)) {
		b = append(b, byte(r), byte(r>>8))
	}
	return b
}
