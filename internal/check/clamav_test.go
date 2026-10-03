package check

import (
	"strings"
	"testing"
	"time"
)

// ClamAV definitions are checked like Defender's: built within 7 days.
func TestClamAV(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.Local)
	rs := EvaluateClamAV("ClamAV 1.0.7/27412/Thu Oct  1 08:23:12 2026\n", true, "active", now)
	if len(rs) != 2 || rs[0].Status != Pass || !strings.Contains(rs[0].Have, "daily 27412 · built on 1 Oct 2026 08:23 (2 days old) · engine 1.0.7") || rs[1].Status != Pass {
		t.Errorf("current: %+v", rs)
	}
	rs = EvaluateClamAV("ClamAV 1.0.7/27380/Sat Sep 12 08:00:00 2026\n", true, "inactive", now)
	if rs[0].Status != Fail || rs[0].Fix == "" || rs[1].Status != Warn {
		t.Errorf("old: %+v", rs)
	}
	if rs = EvaluateClamAV("ClamAV 1.0.7\n", true, "", now); rs[0].Status != Fail || !strings.Contains(rs[0].Have, "No definitions") || rs[1].Status != Info {
		t.Errorf("no database: %+v", rs)
	}
	if rs = EvaluateClamAV("", false, "", now); len(rs) != 1 || rs[0].Status != Info {
		t.Errorf("not installed: %+v", rs)
	}
}
