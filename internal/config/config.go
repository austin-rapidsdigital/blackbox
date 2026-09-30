// Package config loads blackbox.conf, a plain "key = value" file.
//
// A flat format keeps Blackbox free of third-party parsing libraries and
// is easy to edit in Notepad or vi. Lines starting with # are comments;
// lists are comma-separated.
package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Config holds all settings. Zero values are replaced by defaults.
type Config struct {
	SiteName         string
	ReportEvery      string   // daily | weekly | monthly
	RetentionDays    int      // 0 = keep forever
	ExcludeUsers     []string // accounts to leave out (case-insensitive)
	ExcludeProcesses []string // program names/paths to leave out
	SignatureBlock   bool
	ReviewRoles      []string
	DataDir          string

	Path string // file the config was loaded from ("" if defaults)
}

// Default returns the built-in defaults.
func Default() *Config {
	return &Config{
		ReportEvery:    "weekly",
		SignatureBlock: true,
		ReviewRoles:    []string{"ISSO / Auditor", "ISSM"},
		DataDir:        DefaultDataDir(),
	}
}

// DefaultDataDir is where state, collected events and reports live.
func DefaultDataDir() string {
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "Blackbox")
	}
	return "/var/lib/blackbox"
}

// DefaultPath is where the config file is looked for.
func DefaultPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(DefaultDataDir(), "blackbox.conf")
	}
	return "/etc/blackbox/blackbox.conf"
}

// Load reads path. A missing file yields defaults (no error).
func Load(path string) (*Config, error) {
	c := Default()
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	c.Path = path
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected key = value", path, n)
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(stripComment(v))
		if err := c.set(k, v); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return c, c.Validate()
}

// stripComment removes a trailing " # comment" (a # preceded by space).
func stripComment(v string) string {
	if i := strings.Index(v, " #"); i >= 0 {
		return v[:i]
	}
	return v
}

func (c *Config) set(k, v string) error {
	switch k {
	case "site_name":
		c.SiteName = v
	case "report_every":
		if v != "" {
			c.ReportEvery = strings.ToLower(v)
		}
	case "retention_days":
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return fmt.Errorf("retention_days must be 0 or a positive number")
		}
		c.RetentionDays = n
	case "exclude_users":
		c.ExcludeUsers = list(v)
	case "exclude_processes":
		c.ExcludeProcesses = list(v)
	case "signature_block":
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("signature_block must be true or false")
		}
		c.SignatureBlock = b
	case "review_roles":
		if l := list(v); len(l) > 0 {
			c.ReviewRoles = l
		}
	case "data_dir":
		if v != "" {
			c.DataDir = v
		}
	default:
		return fmt.Errorf("unknown setting %q", k)
	}
	return nil
}

// Validate checks values that can be wrong.
func (c *Config) Validate() error {
	switch c.ReportEvery {
	case "daily", "weekly", "monthly":
	default:
		return fmt.Errorf("report_every must be daily, weekly or monthly (got %q)", c.ReportEvery)
	}
	return nil
}

func list(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Template is the commented config written by `blackbox install`.
const Template = `# Blackbox configuration
# Lines starting with # are comments. Lists are comma-separated.
# Changes take effect at the next scheduled run.

# Name shown at the top of every report.
site_name = {{SITE}}

# How often a report is produced: daily, weekly or monthly.
# Events are collected every hour regardless, so nothing is lost to log
# rollover even with weekly reports.
report_every = {{REPORT_EVERY}}

# Days to keep reports and collected events. 0 = keep forever.
retention_days = 0

# Accounts and programs to leave out of reports (for known noisy service
# accounts or tools). Example:
#   exclude_users = svc_backup, svc_scanner
#   exclude_processes = C:\Tools\Scanner\scan.exe
exclude_users =
exclude_processes =

# Printable review/signature block at the end of each report.
signature_block = true
review_roles = ISSO / Auditor, ISSM
`

// Render fills in Template.
func Render(site, reportEvery string) string {
	return strings.NewReplacer("{{SITE}}", site, "{{REPORT_EVERY}}", reportEvery).Replace(Template)
}
