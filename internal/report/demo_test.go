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
		res := []check.Result{{Area: "Audit policy", Item: "Logon", Status: check.Pass}, {Area: "Baseline", Item: s.baseline, Status: check.Info}}
		if s.name == "WS-13" || s.name == "alma-db01" {
			res = append(res, check.Result{Area: "Audit policy", Item: "Removable storage", Status: check.Fail})
		}
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
