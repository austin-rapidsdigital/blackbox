package report

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// A13: a fresh Server 2025 registers firewall rules for its app packages
// (by NT SERVICE\mpssvc); they are one Info row a day, and a person
// enabling SMB-In keeps a row of its own.
func TestAppPackageFirewallRules(t *testing.T) {
	at := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	var evs []*event.Event
	add := func(i int, action, user, rule string, sev event.Severity) {
		evs = append(evs, &event.Event{Time: at.Add(time.Duration(i) * time.Second), Host: "WIN-SRV", OS: "windows", Category: event.CatIntegrity,
			Severity: sev, Action: action, User: user, Target: rule, Summary: action + " " + rule})
	}
	for i := 0; i < 74; i++ {
		add(i, "firewall_rule_added", `NT SERVICE\mpssvc`, fmt.Sprintf("@{Microsoft.AAD.BrokerPlugin_1000.19580.1000.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources/PackageDisplayName}%d", i), event.SevLow)
	}
	for i := 0; i < 32; i++ {
		add(100+i, "firewall_rule_deleted", `NT SERVICE\mpssvc`, fmt.Sprintf("@{Microsoft.Windows.Search_1.0?ms-resource://x}%d", i), event.SevMedium)
	}
	for i := 0; i < 17; i++ {
		add(200+i, "firewall_rule_changed", `NT SERVICE\mpssvc`, fmt.Sprintf("@{Microsoft.Windows.Photos_1.0?ms-resource://x}%d", i), event.SevLow)
	}
	add(300, "firewall_rule_changed", `WIN-SRV\claude`, "File and Printer Sharing (SMB-In)", event.SevLow)
	r := Build(evs, nil, Options{Location: time.UTC, WindowEnd: at.Add(24 * time.Hour)})
	var rows []string
	for _, e := range r.Events {
		rows = append(rows, string(e.Severity)+" "+e.Summary)
	}
	want := []string{
		"info Windows updated the firewall rules for its built-in app packages: 74 added, 17 changed, 32 deleted (by the Windows Firewall service).",
		"low firewall_rule_changed File and Printer Sharing (SMB-In)",
	}
	if strings.Join(rows, "\n") != strings.Join(want, "\n") {
		t.Errorf("rows:\n%s", strings.Join(rows, "\n"))
	}
}

// W1: events stored under a new server's name from before setup renamed
// it are shown on that server, not as a third system.
func TestFormerNameIsNotASystem(t *testing.T) {
	at := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	evs := []*event.Event{
		{Time: at, Host: "WIN-R5L5B9EF403", OS: "windows", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "a"},
		{Time: at.Add(time.Minute), Host: "SRV25", OS: "windows", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "b"},
		{Time: at.Add(2 * time.Minute), Host: "ubuntu-server", OS: "linux", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "c"},
	}
	systems := []SystemInfo{{Name: "SRV25", OS: "windows"}, {Name: "ubuntu-server", OS: "linux", Via: "SRV25"}}
	r := Build(evs, nil, Options{Location: time.UTC, WindowEnd: at.Add(time.Hour), Systems: systems, Collector: true})
	if strings.Join(r.Hosts, ",") != "SRV25,ubuntu-server" || detail(r.Events[0], "Recorded under") != "its former name WIN-R5L5B9EF403" {
		t.Errorf("hosts %v; first row %+v", r.Hosts, r.Events[0])
	}
}
