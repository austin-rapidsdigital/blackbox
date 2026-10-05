package collect

import (
	"errors"
	"strings"
	"testing"
)

// L3: each collection checks that auditing is running.
func TestAuditOffText(t *testing.T) {
	on := "enabled 2\nfailure 1\npid 812\nbacklog_limit 8192\nlost 0\n"
	if s := AuditOffText(on, nil, "active\n"); s != "" {
		t.Errorf("running: %q", s)
	}
	if s := AuditOffText(strings.Replace(on, "enabled 2", "enabled 0", 1), nil, "active\n"); !strings.Contains(s, "kernel auditing is off") {
		t.Errorf("enabled 0: %q", s)
	}
	if s := AuditOffText(on, nil, "inactive\n"); !strings.Contains(s, "auditd) is not running") {
		t.Errorf("stopped: %q", s)
	}
	if s := AuditOffText("", errors.New("no auditctl"), ""); s != "" {
		t.Errorf("can't tell: %q", s)
	}
}
