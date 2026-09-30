// Package install sets Blackbox up to run on a schedule.
package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/config"
)

// Options for install.
type Options struct {
	Site         string
	ReportEvery  string
	ReportDir    string // "" = the default reports folder
	CollectEvery time.Duration
	Version      string
	Logf         func(format string, args ...any)
}

// writeConfig creates the config file, or updates these settings in an
// existing one (keeping everything else, including comments).
func writeConfig(path string, opt Options, crlf bool) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		text := config.Render(opt.Site, opt.ReportEvery, opt.ReportDir, opt.CollectEvery)
		if crlf {
			text = strings.ReplaceAll(text, "\n", "\r\n") // friendly for Notepad
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		return os.WriteFile(path, []byte(text), 0o640)
	}
	return config.SetValues(path, [][2]string{
		{"site_name", opt.Site},
		{"report_every", opt.ReportEvery},
		{"report_dir", opt.ReportDir},
		{"collect_every", config.FormatDuration(opt.CollectEvery)},
	})
}

// PrepareReportDir makes sure reports can be written to dir. A folder that
// does not exist yet is created and restricted to administrators (Windows)
// or root (Linux); an existing folder's permissions are left exactly as
// they are, so a folder you have already locked down stays that way.
func PrepareReportDir(dir string, logf func(string, ...any)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if !config.IsAbs(dir) {
		return fmt.Errorf("report folder must be a full path (got %q)", dir)
	}
	fi, err := os.Stat(dir)
	switch {
	case os.IsNotExist(err):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create report folder %s: %w", dir, err)
		}
		if err := restrictDir(dir); err != nil {
			return err
		}
		logf("Report folder:       %s (created; administrators only)", dir)
	case err != nil:
		return fmt.Errorf("report folder %s: %w", dir, err)
	case !fi.IsDir():
		return fmt.Errorf("report folder %s is a file, not a folder", dir)
	default:
		logf("Report folder:       %s (existing folder; its permissions were not changed)", dir)
	}
	if err := CheckWritable(dir); err != nil {
		return err
	}
	if strings.HasPrefix(dir, `\\`) {
		logf("                     Scheduled runs write to this share as the computer account (DOMAIN\\COMPUTER$);")
		logf("                     make sure it has write access to the share and folder.")
	}
	return nil
}

// CheckWritable confirms a file can be created in dir.
func CheckWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".blackbox-write-test-*")
	if err != nil {
		return fmt.Errorf("cannot write to %s: %w", dir, err)
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return nil
}

// SetReportDir moves future reports to dir (or back to the default when
// dir is ""), after checking the folder, and updates what the scheduled
// job is allowed to write to. Existing reports are not moved.
func SetReportDir(cfgPath, dir string, logf func(string, ...any)) error {
	if dir != "" {
		if err := PrepareReportDir(dir, logf); err != nil {
			return err
		}
	}
	if err := config.SetValue(cfgPath, "report_dir", dir); err != nil {
		return err
	}
	return afterReportDirChange(logf)
}

// TaskName is the Windows scheduled task name.
const TaskName = "Blackbox Audit Collection"

// taskXML is a Task Scheduler definition: run as SYSTEM with highest
// privileges, every interval indefinitely, catch up after the system was
// off, and never run two copies at once.
func taskXML(exe string, every time.Duration, start time.Time) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Blackbox</Author>
    <Description>Collects security-relevant events before logs roll over and produces Blackbox audit reports.</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>%s</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>%s</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT5M</Delay>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT2H</ExecutionTimeLimit>
    <Enabled>true</Enabled>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%s</Command>
      <Arguments>run</Arguments>
    </Exec>
  </Actions>
</Task>
`, isoDuration(every), start.Format("2006-01-02T15:04:05"), xmlEscape(exe))
}

// isoDuration formats d as an ISO 8601 duration (PT1H, PT15M).
func isoDuration(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("PT%dH", int(d.Hours()))
	}
	return fmt.Sprintf("PT%dM", int(d.Minutes()))
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

// systemdService is the unit that runs one collection (and a report when
// one is due). It is sandboxed: no network, read-only system, and the only
// writable places are Blackbox's data folder and the report folder.
func systemdService(exe string, writable ...string) string {
	return fmt.Sprintf(`[Unit]
Description=Blackbox audit log collection and reporting
Documentation=https://github.com/casea1/blackbox
After=auditd.service local-fs.target

[Service]
Type=oneshot
ExecStart=%s run
Nice=10
IOSchedulingClass=idle
PrivateNetwork=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%s
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
UMask=0077
TimeoutStartSec=2h
`, exe, strings.Join(uniq(writable), " "))
}

func uniq(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// systemdTimer runs the service on a fixed schedule and catches up after
// the system was off (Persistent=true).
func systemdTimer(every time.Duration) (string, error) {
	cal, err := onCalendar(every)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`[Unit]
Description=Run Blackbox audit collection every %s

[Timer]
OnCalendar=%s
OnBootSec=5min
Persistent=true
RandomizedDelaySec=60

[Install]
WantedBy=timers.target
`, every, cal), nil
}

// onCalendar turns an interval into a systemd calendar expression. The
// interval must divide an hour (minutes) or a day (hours) evenly.
func onCalendar(d time.Duration) (string, error) {
	switch {
	case d < time.Hour && d >= time.Minute && time.Hour%d == 0 && d%time.Minute == 0:
		return fmt.Sprintf("*-*-* *:00/%d:00", int(d.Minutes())), nil
	case d >= time.Hour && d%time.Hour == 0 && (24*time.Hour)%d == 0:
		return fmt.Sprintf("*-*-* 00/%d:05:00", int(d.Hours())), nil
	}
	return "", fmt.Errorf("collection interval %s must divide an hour or a day evenly (e.g. 15m, 30m, 1h, 2h)", d)
}
