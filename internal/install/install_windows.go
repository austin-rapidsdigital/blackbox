//go:build windows

package install

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/casea1/blackbox/internal/config"
)

// ProgramPath is where install copies the executable.
func ProgramPath() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "Blackbox", "blackbox.exe")
}

// Install copies the program, creates the data folder and config, and
// registers the scheduled task. It is safe to run again (upgrade).
func Install(opt Options) error {
	logf := opt.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if !isAdmin() {
		return errors.New("install must be run from an elevated (Run as administrator) prompt")
	}

	// 1. Program files.
	self, err := os.Executable()
	if err != nil {
		return err
	}
	dst := ProgramPath()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if !samePath(self, dst) {
		if err := copyFile(self, dst); err != nil {
			return fmt.Errorf("copy program to %s: %w (if upgrading, make sure Blackbox is not running)", dst, err)
		}
	}
	logf("Installed program:   %s", dst)

	// 2. Data folder, readable only by Administrators and SYSTEM (SIDs are
	// used so this works on any language version of Windows).
	data := config.DefaultDataDir()
	if err := os.MkdirAll(data, 0o750); err != nil {
		return err
	}
	if out, err := exec.Command("icacls.exe", data, "/inheritance:r",
		"/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F").CombinedOutput(); err != nil {
		return fmt.Errorf("restrict permissions on %s: %v: %s", data, err, out)
	}
	logf("Data folder:         %s (Administrators and SYSTEM only)", data)

	// 3. Config (kept if it already exists, so upgrades keep settings).
	cfgPath := config.DefaultPath()
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		text := config.Render(opt.Site, opt.ReportEvery)
		text = strings.ReplaceAll(text, "\n", "\r\n") // friendly for Notepad
		if err := os.WriteFile(cfgPath, []byte(text), 0o640); err != nil {
			return err
		}
		logf("Configuration:       %s", cfgPath)
	} else {
		logf("Configuration:       %s (kept existing file)", cfgPath)
	}

	// 4. Scheduled task.
	start := time.Now().Truncate(time.Hour).Add(5 * time.Minute)
	xml := taskXML(dst, opt.CollectEvery, start)
	tmp := filepath.Join(data, "blackbox-task.xml")
	if err := os.WriteFile(tmp, utf16LE(xml), 0o640); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if out, err := exec.Command("schtasks.exe", "/Create", "/TN", TaskName, "/XML", tmp, "/F").CombinedOutput(); err != nil {
		return fmt.Errorf("create scheduled task: %v: %s", err, strings.TrimSpace(string(out)))
	}
	logf("Scheduled task:      \"%s\" — collects every %s as SYSTEM; %s reports", TaskName, opt.CollectEvery, opt.ReportEvery)
	return nil
}

// Uninstall removes the scheduled task. Reports and collected data are
// kept; the program file is left for the administrator to delete.
func Uninstall(logf func(string, ...any)) error {
	if !isAdmin() {
		return errors.New("uninstall must be run from an elevated (Run as administrator) prompt")
	}
	out, err := exec.Command("schtasks.exe", "/Delete", "/TN", TaskName, "/F").CombinedOutput()
	if err != nil {
		return fmt.Errorf("remove scheduled task: %v: %s", err, strings.TrimSpace(string(out)))
	}
	logf("Removed scheduled task \"%s\".", TaskName)
	logf("Reports and collected events were kept in %s.", config.DefaultDataDir())
	logf("To remove the program, delete %s.", filepath.Dir(ProgramPath()))
	return nil
}

// isAdmin checks for an elevated token by opening the raw physical disk,
// which only administrators can do.
func isAdmin() bool {
	f, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func samePath(a, b string) bool {
	aa, err1 := filepath.Abs(a)
	bb, err2 := filepath.Abs(b)
	return err1 == nil && err2 == nil && strings.EqualFold(aa, bb)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// utf16LE encodes s with a byte order mark, as schtasks expects.
func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2+2*len(u))
	b[0], b[1] = 0xFF, 0xFE
	for i, c := range u {
		b[2+2*i] = byte(c)
		b[3+2*i] = byte(c >> 8)
	}
	return b
}
