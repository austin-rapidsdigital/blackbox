package install

import (
	"encoding/xml"
	"strings"
	"testing"
	"time"
)

func TestTaskXML(t *testing.T) {
	x := taskXML(`C:\Program Files\Blackbox\blackbox.exe`, 15*time.Minute, time.Date(2026, 9, 29, 10, 5, 0, 0, time.UTC))
	for _, want := range []string{"<Interval>PT15M</Interval>", "<UserId>S-1-5-18</UserId>", "<StartWhenAvailable>true</StartWhenAvailable>", `<Command>C:\Program Files\Blackbox\blackbox.exe</Command>`} {
		if !strings.Contains(x, want) {
			t.Errorf("task XML missing %s", want)
		}
	}
	dec := xml.NewDecoder(strings.NewReader(strings.Replace(x, `encoding="UTF-16"`, `encoding="UTF-8"`, 1)))
	for {
		if _, err := dec.Token(); err != nil {
			if err.Error() != "EOF" {
				t.Fatalf("task XML is not well-formed: %v", err)
			}
			break
		}
	}
	if isoDuration(time.Hour) != "PT1H" {
		t.Error("isoDuration(1h)")
	}
}

func TestSystemdUnits(t *testing.T) {
	for d, want := range map[time.Duration]string{
		time.Hour: "*-*-* 00/1:05:00", 15 * time.Minute: "*-*-* *:00/15:00", 2 * time.Hour: "*-*-* 00/2:05:00",
	} {
		got, err := onCalendar(d)
		if err != nil || got != want {
			t.Errorf("onCalendar(%s) = %q, %v; want %q", d, got, err, want)
		}
	}
	for _, bad := range []time.Duration{7 * time.Minute, 5 * time.Hour} {
		if _, err := onCalendar(bad); err == nil {
			t.Errorf("onCalendar(%s) should fail", bad)
		}
	}
	timer, _ := systemdTimer(time.Hour)
	svc := systemdService("/usr/local/bin/blackbox", "/var/lib/blackbox")
	for _, want := range []string{"Persistent=true", "WantedBy=timers.target"} {
		if !strings.Contains(timer, want) {
			t.Errorf("timer missing %s", want)
		}
	}
	for _, want := range []string{"ExecStart=/usr/local/bin/blackbox run", "PrivateNetwork=yes", "ProtectSystem=strict", "ReadWritePaths=/var/lib/blackbox"} {
		if !strings.Contains(svc, want) {
			t.Errorf("service missing %s", want)
		}
	}
}
