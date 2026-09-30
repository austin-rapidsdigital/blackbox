//go:build linux

package install

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/casea1/blackbox/internal/config"
)

// ProgramPath is where install copies the executable.
func ProgramPath() string { return "/usr/local/bin/blackbox" }

const (
	serviceFile = "/etc/systemd/system/blackbox.service"
	timerFile   = "/etc/systemd/system/blackbox.timer"
)

// Install copies the program, creates the data folder and config, and
// enables the systemd timer. It is safe to run again (upgrade).
func Install(opt Options) error {
	logf := opt.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if os.Geteuid() != 0 {
		return errors.New("install must be run as root (sudo ./blackbox install)")
	}
	timer, err := systemdTimer(opt.CollectEvery)
	if err != nil {
		return err
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}
	dst := ProgramPath()
	if resolved, _ := filepath.EvalSymlinks(self); resolved != dst {
		if err := copyFile(self, dst, 0o755); err != nil {
			return fmt.Errorf("copy program to %s: %w", dst, err)
		}
	}
	logf("Installed program:   %s", dst)

	data := config.DefaultDataDir()
	if err := os.MkdirAll(data, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(data, 0o700); err != nil {
		return err
	}
	logf("Data folder:         %s (root only)", data)

	cfgPath := config.DefaultPath()
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if err := os.WriteFile(cfgPath, []byte(config.Render(opt.Site, opt.ReportEvery)), 0o640); err != nil {
			return err
		}
		logf("Configuration:       %s", cfgPath)
	} else {
		logf("Configuration:       %s (kept existing file)", cfgPath)
	}

	if err := os.WriteFile(serviceFile, []byte(systemdService(dst, data)), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(timerFile, []byte(timer), 0o644); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", "blackbox.timer"}} {
		if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	logf("Scheduled:           blackbox.timer — collects every %s as root; %s reports", opt.CollectEvery, opt.ReportEvery)
	return nil
}

// Uninstall disables the timer and removes the unit files. Reports and
// collected data are kept.
func Uninstall(logf func(string, ...any)) error {
	if os.Geteuid() != 0 {
		return errors.New("uninstall must be run as root")
	}
	exec.Command("systemctl", "disable", "--now", "blackbox.timer").Run()
	for _, f := range []string{timerFile, serviceFile} {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	exec.Command("systemctl", "daemon-reload").Run()
	logf("Removed the blackbox.timer schedule.")
	logf("Reports and collected events were kept in %s.", config.DefaultDataDir())
	logf("To remove the program: rm %s (and %s if no longer needed).", ProgramPath(), filepath.Dir(config.DefaultPath()))
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
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
