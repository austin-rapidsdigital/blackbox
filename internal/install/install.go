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
