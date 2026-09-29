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
