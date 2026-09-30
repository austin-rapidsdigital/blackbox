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
	if opt.ReportDir != "" {
		if err := PrepareReportDir(opt.ReportDir, logf); err != nil {
			return err
		}
	}

	// Config: created, or updated with these settings on a re-install.
	cfgPath := config.DefaultPath()
	if err := writeConfig(cfgPath, opt, false); err != nil {
		return err
	}
	logf("Configuration:       %s", cfgPath)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	if err := os.WriteFile(serviceFile, []byte(systemdService(dst, data, cfg.ReportsDir())), 0o644); err != nil {
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
	logf("Scheduled:           blackbox.timer — collects %s as root; %s reports", EveryText(opt.CollectEvery), opt.ReportEvery)
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
	if cfg, _ := config.Load(config.DefaultPath()); cfg != nil {
		logf("Reports were kept in %s.", cfg.ReportsDir())
	}
	logf("Collected events were kept in %s.", config.DefaultDataDir())
	logf("To remove the program: rm %s (and %s if no longer needed).", ProgramPath(), filepath.Dir(config.DefaultPath()))
	return nil
}

// afterReportDirChange lets the sandboxed service write to the new report
// folder (systemd ReadWritePaths), if Blackbox is installed.
func afterReportDirChange(logf func(string, ...any)) error {
	if _, err := os.Stat(serviceFile); err != nil {
		return nil // not installed as a service
	}
	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		return err
	}
	if err := os.WriteFile(serviceFile, []byte(systemdService(ProgramPath(), config.DefaultDataDir(), cfg.ReportsDir())), 0o644); err != nil {
		return err
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %v: %s", err, strings.TrimSpace(string(out)))
	}
	logf("Updated blackbox.service so it may write to %s.", cfg.ReportsDir())
	return nil
}

// restrictDir limits a folder Blackbox created to root.
func restrictDir(dir string) error { return os.Chmod(dir, 0o700) }

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

// RequireAdmin returns an error unless running as root.
func RequireAdmin() error {
	if os.Geteuid() != 0 {
		return errors.New("run this as root (sudo)")
	}
	return nil
}
