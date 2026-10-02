package report

import (
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// TestDemoReport writes a realistic LAN report (24 systems, like the
// approved mockups in docs/redesign) to BLACKBOX_DEMO_OUT, for screenshots.
// BLACKBOX_DEMO_STANDALONE=1 writes a one-computer report with a VM.
func TestDemoReport(t *testing.T) {
	out := os.Getenv("BLACKBOX_DEMO_OUT")
	if out == "" {
		t.Skip("set BLACKBOX_DEMO_OUT")
	}
	standalone := os.Getenv("BLACKBOX_DEMO_STANDALONE") != ""
	rnd := rand.New(rand.NewSource(7))
	end := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -7)

	type sys struct {
		name, os, baseline, via string
		silent                  bool
	}
	var systems []sys
	if standalone {
		systems = []sys{{name: "ENG-WS-21", os: "windows", baseline: "Windows 11 STIG V2R8"}, {name: "ENG-WS-21-VM1", os: "linux", baseline: "Ubuntu 24.04 STIG V1R3", via: "ENG-WS-21"}}
	} else {
		systems = []sys{{name: "SRV-DC01", os: "windows", baseline: "Windows Server 2025 STIG V1R1"}, {name: "SRV-FS01", os: "windows", baseline: "Windows Server 2025 STIG V1R1"},
			{name: "alma-build01", os: "linux", baseline: "Alma 8 (RHEL 8 STIG)"}, {name: "alma-db01", os: "linux", baseline: "Alma 8 (RHEL 8 STIG)"}}
		for i := 1; i <= 14; i++ {
			systems = append(systems, sys{name: fmt.Sprintf("WS-%02d", i), os: "windows", baseline: "Windows 11 STIG V2R8", silent: i == 9})
		}
		for _, n := range []string{"ubu-ws10", "ubu-ws11", "ubu-ws12", "ubu-ws13"} {
			systems = append(systems, sys{name: n, os: "linux", baseline: "Ubuntu 24.04 STIG V1R3"})
		}
		systems = append(systems, sys{name: "WS-03-VM1", os: "windows", baseline: "Windows 11 STIG V2R8", via: "WS-03"}, sys{name: "ubu-ws12-vm", os: "linux", baseline: "Ubuntu 24.04 STIG V1R3", via: "ubu-ws12"})
	}
	users := []string{"admin_jd", "jsmith", "mjones", "kpatel", "lnguyen", "rgarcia", "bwilliams", "dchen"}
	var events []*event.Event
	var runs []*store.Run
	var infos []SystemInfo
	var checks []CheckSet
	add := func(at time.Time, host string, cat event.Category, sev event.Severity, action, user, summary string) *event.Event {
		e := &event.Event{Time: at, Host: host, OS: "windows", Source: "Security", Category: cat, Severity: sev, Action: action,
			User: user, Summary: summary, Outcome: "success", SourceIP: fmt.Sprintf("10.1.1.%d", 10+rnd.Intn(50))}
		events = append(events, e)
		return e
	}
	for _, s := range systems {
		last := end.Add(-5 * time.Minute)
		if s.silent {
			last = start.Add(-10 * time.Hour)
		}
		infos = append(infos, SystemInfo{Name: s.name, OS: s.os, Via: s.via, FirstSeen: start.AddDate(0, -3, 0), LastRun: last})
		for h := start.Add(time.Hour); !h.After(last); h = h.Add(time.Hour) {
			runs = append(runs, &store.Run{Time: h, Host: s.name, OS: s.os, Version: "0.9.0"})
		}
		res := demoChecks(s.os, s.baseline, s.name)
		cs := NewCheckSet(s.name, end.Add(-time.Hour), res)
		cs.Baseline = s.baseline
		checks = append(checks, cs)
		n := 1500 + rnd.Intn(2500)
		if s.silent {
			continue
		}
		owner := users[rnd.Intn(len(users))]
		for i := 0; i < n; i++ {
			// Mostly working hours on weekdays.
			at := start.Add(time.Duration(rnd.Intn(7))*24*time.Hour + time.Duration(7+rnd.Intn(10))*time.Hour + time.Duration(rnd.Intn(3600))*time.Second)
			if rnd.Intn(1500) == 0 {
				at = at.Add(8 * time.Hour)
			}
			weekend := at.Weekday() == time.Saturday || at.Weekday() == time.Sunday
			if weekend && rnd.Intn(10) > 0 {
				continue // a little weekend work: logons only
			}
			if at.After(last) {
				continue
			}
			u := owner
			if rnd.Intn(5) == 0 {
				u = users[rnd.Intn(len(users))]
			}
			switch r := rnd.Intn(100); {
			case weekend:
				add(at, s.name, event.CatLogon, event.SevInfo, "logon", u, u+" logged on at the console.")
			case r < 70:
				add(at, s.name, event.CatLogon, event.SevInfo, "logon", u, u+" logged on (Remote Desktop) from 10.1.1.42.")
			case r < 95:
				add(at, s.name, event.CatPrivileged, event.SevLow, "elevated_process", u, u+` ran with administrator rights: C:\Windows\System32\mmc.exe`)
			case r < 96 && rnd.Intn(4) == 0:
				add(at, s.name, event.CatFailedLogon, event.SevLow, "logon_failed", "", "Logon failed for "+u+": bad password.").Target = u
			default:
				dev := []string{"SanDisk Cruzer Blade", "Kingston DataTraveler 3.0", "Samsung T7", "Logitech USB receiver"}[rnd.Intn(4)]
				add(at, s.name, event.CatRemovable, event.SevMedium, "usb_connected", u, "USB storage connected: "+dev+".").Target = dev
			}
		}
	}
	if !standalone {
		// The mockups' story: WS-07 cleared its log, someone guessed passwords.
		day := end.AddDate(0, 0, -2)
		add(day.Add(9*time.Hour+20*time.Minute), "WS-07", event.CatAccount, event.SevHigh, "group_member_added", "admin_jd", "admin_jd added tempuser to the privileged group Administrators.").Target = "tempuser"
		add(day.Add(9*time.Hour+38*time.Minute), "WS-07", event.CatIntegrity, event.SevHigh, "audit_policy_changed", "admin_jd", "admin_jd changed the audit policy: Removable Storage → No auditing.")
		add(day.Add(12*time.Hour+38*time.Minute), "WS-07", event.CatIntegrity, event.SevHigh, "log_cleared", "admin_jd", "The Security log was cleared by admin_jd.")
		add(day.Add(12*time.Hour+40*time.Minute), "WS-07", event.CatIntegrity, event.SevHigh, "log_cleared", "admin_jd", "The Security log was cleared by admin_jd.")
		for i := 0; i < 8; i++ {
			e := add(day.Add(6*time.Hour+time.Duration(i*5)*time.Second), "WS-07", event.CatFailedLogon, event.SevLow, "logon_failed", "", "Logon failed for administrator: bad password.")
			e.Target, e.SourceIP = "administrator", "10.1.1.99"
		}
		add(day.Add(-48*time.Hour+11*time.Hour), "SRV-DC01", event.CatAccount, event.SevHigh, "group_member_added", "admin_jd", "admin_jd added mjones to the privileged group Domain Admins.").Target = "mjones"
		add(day.Add(-60*time.Hour), "WS-11", event.CatFailedLogon, event.SevMedium, "account_locked", "rgarcia", "Account rgarcia was locked out after too many failed logon attempts.")
	}
	var history []Summary
	for w := 11; w >= 1; w-- {
		history = append(history, Summary{WindowEnd: end.AddDate(0, 0, -7*w), Detections: make([]Detection, 2+rnd.Intn(6)), Events: 70000 + rnd.Intn(15000),
			Metrics: map[string]int{MHighEvents: rnd.Intn(5), MFailedLogons: 110 + rnd.Intn(40), MPrivileged: 11000 + rnd.Intn(2000),
				MSystems: 23 + rnd.Intn(2), MLockouts: rnd.Intn(2), MUSB: 2000 + rnd.Intn(600), MAccountChanges: 3 + rnd.Intn(4)}})
	}
	site := "Lab 3 LAN"
	if standalone {
		site = ""
	}
	r := Build(events, runs, Options{Site: site, WindowStart: start, WindowEnd: end, Generated: end.Add(5 * time.Minute), Location: time.UTC,
		Source: "Live collection", Collector: !standalone, Systems: infos, CheckSets: checks, History: history, Period: "weekly",
		KnownDevices: map[string]time.Time{}, WorkingHours: mustHours("Mon-Fri 06:00-18:00")})
	os.RemoveAll(out)
	if err := r.Write(out); err != nil {
		t.Fatal(err)
	}
}

func mustHours(v string) config.WorkingHours {
	w, err := config.ParseWorkingHours(v)
	if err != nil {
		panic(err)
	}
	return w
}

// demoChecks is a realistic audit settings check: everything matching,
// except a few gaps on named systems.
func demoChecks(os, baseline, name string) []check.Result {
	sf := "Success and Failure"
	res := []check.Result{{Area: "Baseline", Item: "Compared with", Status: check.Info, Have: baseline, Want: baseline}}
	if os == "windows" {
		for _, x := range [][3]string{{"Logon", sf, "WN11-AU-000070, -075"}, {"Logoff", "Success", "WN11-AU-000065"},
			{"Credential Validation", sf, "WN11-AU-000005, -010"}, {"User Account Management", sf, "WN11-AU-000035, -040"},
			{"Security Group Management", "Success", "WN11-AU-000030"}, {"Audit Policy Change", "Success", "WN11-AU-000100"},
			{"Sensitive Privilege Use", sf, "WN11-AU-000110, -115"}, {"Process Creation", "Success", "WN11-AU-000050"},
			{"Removable Storage", sf, "WN11-AU-000085, -090"}} {
			r := check.Result{Area: "Audit policy", Item: x[0], Want: x[1], Have: x[1], STIG: x[2], Status: check.Pass}
			if x[0] == "Removable Storage" && name == "WS-13" {
				r.Have, r.Status = "No auditing", check.Fail
				r.Affects = "USB & Removable Media (files read/written)"
				r.Fix = "Group Policy: Advanced Audit Policy > Object Access > Audit Removable Storage: Success and Failure"
			}
			res = append(res, r)
		}
		ps := check.Result{Area: "Audit settings", Item: "PowerShell script block logging", Want: "Enabled (1)", Have: "Enabled (1)", STIG: "WN11-CC-000326", Status: check.Pass}
		if name == "WS-12" {
			ps.Have, ps.Status = "Not set", check.Warn
			ps.Fix = "Group Policy: Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging"
		}
		res = append(res, ps, check.Result{Area: "Event log size", Item: "Security log", Want: "Holds a week", Have: "Holds 9 days (1 GB)", STIG: "WN11-AU-000505", Status: check.Pass})
		return res
	}
	for _, x := range []string{"Watch /etc/passwd", "Watch /etc/shadow", "Watch /etc/sudoers and /etc/sudoers.d", "Programs run with raised privileges (execve, uid!=euid)",
		"Commands run as root by a person (execve, euid=0, auid set)", "Filesystem mounts", "Audit configuration watched (/etc/audit)"} {
		r := check.Result{Area: "Audit rules", Item: x, Want: "Present", Have: "Present", Status: check.Pass}
		if x == "Filesystem mounts" && name == "alma-db01" {
			r.Have, r.Status = "Missing", check.Fail
			r.Affects = "USB & Removable Media (disks mounted from the command line)"
			r.Fix = "blackbox check --audit-rules --missing | install -m 0600 /dev/stdin /etc/audit/rules.d/blackbox.rules, then augenrules --load"
		}
		res = append(res, r)
	}
	return append(res, check.Result{Area: "Audit service", Item: "auditd running", Want: "active", Have: "active", Status: check.Pass},
		check.Result{Area: "auditd settings", Item: "Audit log space", Want: "a week", Have: "12 days", Status: check.Pass})
}
