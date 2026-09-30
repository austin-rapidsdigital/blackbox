// Package install sets Blackbox up to run on a schedule.
package install

import (
	"fmt"
	"strings"
	"time"
)

// Options for install.
type Options struct {
	Site         string
	ReportEvery  string
	CollectEvery time.Duration
	Logf         func(format string, args ...any)
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
// writable place is Blackbox's data folder.
func systemdService(exe, dataDir string) string {
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
`, exe, dataDir)
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
