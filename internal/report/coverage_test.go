package report

import (
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

// A1: Audit health lists the Security-log events read but not translated,
// with how they appear in the report.
func TestOtherSecurityEventsOnHealth(t *testing.T) {
	end := fx0.Add(24 * time.Hour)
	runs := []*store.Run{{Time: fx0.Add(time.Hour), Host: "WS-07", OS: "windows",
		Channels: []store.ChannelRun{{Channel: "Security", EventCounts: map[int]int{4624: 5, 4910: 3, 5379: 100}}}}}
	r := Build([]*event.Event{{Time: fx0, Host: "WS-07", OS: "windows", Category: event.CatLogon, Severity: event.SevInfo, Action: "logon", Summary: "x"}}, runs,
		Options{WindowEnd: end, Location: time.UTC, Systems: []SystemInfo{{Name: "WS-07", OS: "windows", LastRun: fx0.Add(time.Hour)}}})
	hp := r.healthPage()
	if hp == nil || len(hp.Other) != 2 {
		t.Fatalf("other: %+v", hp)
	}
	if hp.Other[0].ID != 5379 || hp.Other[0].Listed || hp.Other[1].ID != 4910 || !hp.Other[1].Listed || hp.Other[1].Href == "" {
		t.Errorf("other: %+v", hp.Other)
	}
}
