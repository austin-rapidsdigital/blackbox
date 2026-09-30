package event

import (
	"regexp"
	"strings"
)

// masked replaces a secret in a report.
const masked = "********"

var (
	// NAME=value where the name says it is a password or secret, e.g.
	// BLACKBOX_SHARE_PASSWORD='…', DB_PASSWORD=…, $env:SECRET="…".
	secretAssign = regexp.MustCompile(`(?i)(\b[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET)[A-Z0-9_]*\s*=\s*)('[^']*'|"[^"]*"|[^\s;&|]+)`)
	// PowerShell: -Password value, ConvertTo-SecureString 'value' -AsPlainText.
	psPassword   = regexp.MustCompile(`(?i)(-(?:Password|Passwd|Pass)\s+)('[^']*'|"[^"]*"|[^\s;(][^\s;]*)`)
	psSecure     = regexp.MustCompile(`(?i)(ConvertTo-SecureString\s+(?:-String\s+)?)('[^']*'|"[^"]*"|[^\s;]+)`)
	sshpass      = regexp.MustCompile(`(?i)(\bsshpass\s+-p\s*)('[^']*'|"[^"]*"|\S+)`)
	echoIntoSudo = regexp.MustCompile(`(?i)(\b(?:echo|printf)\s+)('[^']*'|"[^"]*"|\S+)(\s*\|\s*sudo\s+-S)`)
	netCommand   = regexp.MustCompile(`(?i)\bnet(?:\.exe)?\s+(user|use)\b(.*)`)
)

// Redact hides passwords typed on a command line. Command-line auditing
// (which the STIG requires) records them as typed; they must not be copied
// into reports.
func Redact(s string) string {
	if s == "" {
		return s
	}
	l := strings.ToLower(s)
	if !strings.Contains(l, "pass") && !strings.Contains(l, "secret") && !strings.Contains(l, "securestring") &&
		!strings.Contains(l, "net") && !strings.Contains(l, "sudo -s") {
		return s // fast path: nothing that could hold a password
	}
	s = secretAssign.ReplaceAllString(s, "${1}"+masked)
	s = psSecure.ReplaceAllString(s, "${1}"+masked)
	s = psPassword.ReplaceAllString(s, "${1}"+masked)
	s = sshpass.ReplaceAllString(s, "${1}"+masked)
	s = echoIntoSudo.ReplaceAllString(s, "${1}"+masked+"${3}")
	if m := netCommand.FindStringSubmatchIndex(s); m != nil {
		s = s[:m[4]] + redactNetArgs(strings.ToLower(s[m[2]:m[3]]), s[m[4]:m[5]])
	}
	return s
}

// redactNetArgs hides the password in "net user NAME PASSWORD" and
// "net use [X:] \\server\share PASSWORD": the first argument after the
// name or share that is not an option (/…) or a prompt (*).
func redactNetArgs(sub, args string) string {
	f := strings.Fields(args)
	pos := 0
	for i, a := range f {
		if strings.HasPrefix(a, "/") || a == "*" {
			continue
		}
		if sub == "use" && pos == 0 && len(a) == 2 && a[1] == ':' {
			continue // drive letter
		}
		pos++
		if pos == 2 {
			f[i] = masked
			return " " + strings.Join(f, " ")
		}
	}
	return args
}

// RedactSecrets removes passwords from everything the event will show or
// store: its summary, command, details and original event data.
func (e *Event) RedactSecrets() {
	e.Summary = Redact(e.Summary)
	e.Command = Redact(e.Command)
	e.Target = Redact(e.Target)
	for i := range e.Details {
		e.Details[i].Value = Redact(e.Details[i].Value)
	}
	if len(e.Fields) > 0 {
		fields := make(map[string]string, len(e.Fields))
		for k, v := range e.Fields {
			fields[k] = Redact(v)
		}
		e.Fields = fields
	}
}
