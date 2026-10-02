package report

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// TestBigReport writes a report of BLACKBOX_BIG synthetic events (a busy
// network's week) to BLACKBOX_BIG_OUT and prints the file sizes. It is
// skipped unless BLACKBOX_BIG is set.
func TestBigReport(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("BLACKBOX_BIG"))
	out := os.Getenv("BLACKBOX_BIG_OUT")
	if n == 0 || out == "" {
		t.Skip("set BLACKBOX_BIG and BLACKBOX_BIG_OUT")
	}
	rnd := rand.New(rand.NewSource(1))
	end := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -7)
	users := []string{"admin_jd", "jsmith", "mjones", "kpatel", "lnguyen", "rgarcia", "bwilliams", "dchen", "svc_patch", "tempuser"}
	type kind struct {
		cat    event.Category
		sev    event.Severity
		action string
		id     int
		weight int
	}
	kinds := []kind{
		{event.CatLogon, event.SevInfo, "logon", 4624, 55},
		{event.CatLogon, event.SevInfo, "logoff", 4634, 25},
		{event.CatPrivileged, event.SevLow, "elevated_process", 4688, 10},
		{event.CatPrivileged, event.SevLow, "admin_logon", 4672, 5},
		{event.CatFailedLogon, event.SevLow, "logon_failed", 4625, 3},
		{event.CatRemovable, event.SevMedium, "usb_connected", 6416, 1},
		{event.CatAccount, event.SevMedium, "password_reset", 4724, 1},
	}
	total := 0
	for _, k := range kinds {
		total += k.weight
	}
	var events []*event.Event
	for i := 0; i < n; i++ {
		w := rnd.Intn(total)
		k := kinds[0]
		for _, x := range kinds {
			if w < x.weight {
				k = x
				break
			}
			w -= x.weight
		}
		host := fmt.Sprintf("WS-%02d", rnd.Intn(30)+1)
		u := users[rnd.Intn(len(users))]
		at := start.Add(time.Duration(rnd.Int63n(int64(end.Sub(start)))))
		events = append(events, &event.Event{Time: at, Host: host, OS: "windows", Source: "Security", EventID: k.id,
			RecordID: uint64(1000000 + i), Category: k.cat, Severity: k.sev, Action: k.action, User: u,
			SourceIP: fmt.Sprintf("10.1.1.%d", rnd.Intn(60)+2), Outcome: "success",
			Summary: fmt.Sprintf("%s %s on %s from 10.1.1.%d", u, k.action, host, rnd.Intn(60)+2),
			Fields: map[string]string{"TargetUserName": u, "LogonType": strconv.Itoa(2 + rnd.Intn(9)), "IpAddress": "10.1.1.9",
				"WorkstationName": host, "ProcessName": `C:\Windows\System32\svchost.exe`, "LogonGuid": fmt.Sprintf("{%08x-0000-0000-0000-000000000000}", rnd.Uint32())}})
	}
	began := time.Now()
	r := Build(events, nil, Options{Site: "Big", WindowStart: start, WindowEnd: end, Generated: end, Location: time.UTC, Collector: true, Period: "weekly"})
	built := time.Since(began)
	os.RemoveAll(out)
	if err := r.Write(out); err != nil {
		t.Fatal(err)
	}
	var data, raw int64
	files, _ := filepath.Glob(filepath.Join(out, "data", "*.js"))
	for _, f := range files {
		st, _ := os.Stat(f)
		if filepath.Ext(f[:len(f)-3]) == "" && len(f) > 7 && f[len(f)-7:] == "-raw.js" {
			raw += st.Size()
		} else {
			data += st.Size()
		}
	}
	html, _ := os.Stat(filepath.Join(out, "report.html"))
	csv, _ := os.Stat(filepath.Join(out, "events.csv"))
	jsonl, _ := os.Stat(filepath.Join(out, "events.jsonl"))
	t.Logf("%d events: build %v, total %v; report.html %d KB; table data %.1f MB; raw event data %.1f MB in %d files; events.csv %.1f MB; events.jsonl %.1f MB",
		n, built.Round(time.Millisecond), time.Since(began).Round(time.Millisecond), html.Size()>>10,
		float64(data)/(1<<20), float64(raw)/(1<<20), len(files), float64(csv.Size())/(1<<20), float64(jsonl.Size())/(1<<20))
}
