package check

import (
	"strings"
	"testing"
	"time"
)

// ClamAV definitions are checked like Defender's: built within 30 days.
func TestClamAV(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.Local)
	rs := EvaluateClamAV("ClamAV 1.0.7/27412/Thu Oct  1 08:23:12 2026\n", true, "active", now)
	if len(rs) != 2 || rs[0].Status != Pass || !strings.Contains(rs[0].Have, "daily 27412 · built on 1 Oct 2026 08:23 (2 days old) · engine 1.0.7") || rs[1].Status != Pass {
		t.Errorf("current: %+v", rs)
	}
	if rs = EvaluateClamAV("ClamAV 1.0.7/27380/Sat Sep 12 08:00:00 2026\n", true, "active", now); rs[0].Status != Pass {
		t.Errorf("21 days old is current: %+v", rs[0])
	}
	rs = EvaluateClamAV("ClamAV 1.0.7/27300/Tue Sep  1 08:00:00 2026\n", true, "inactive", now)
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

// I3: a masked clamd is not advised to be enabled; a scanner in a
// container counts as running; a FIPS host gets a note.
func TestClamAVContainerAndFIPS(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.Local)
	rs := EvaluateClamAV("ClamAV 1.0.7/27412/Thu Oct  1 08:23:12 2026\n", true, ClamMasked, now)
	if rs[1].Status != Info || rs[1].Fix != "" {
		t.Errorf("masked: %+v", rs[1])
	}
	if rs = EvaluateClamAV("ClamAV 1.0.7/27412/Thu Oct  1 08:23:12 2026\n", true, ClamInContainer, now); rs[1].Status != Pass {
		t.Errorf("container: %+v", rs[1])
	}
	if r := EvaluateClamAVFIPS(true); len(r) != 1 || r[0].Status != Info || !strings.Contains(r[0].Have, "FIPS") {
		t.Errorf("fips: %+v", r)
	}
	if EvaluateClamAVFIPS(false) != nil {
		t.Error("note without FIPS")
	}
	if !inContainerCgroup("0::/system.slice/docker-3f2a.scope\n") || inContainerCgroup("0::/system.slice/clamav-daemon.service\n") {
		t.Error("cgroup detection")
	}
}
