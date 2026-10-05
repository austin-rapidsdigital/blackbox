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
	serviceFile  = "/etc/systemd/system/blackbox.service"
	timerFile    = "/etc/systemd/system/blackbox.timer"
	shutdownFile = "/etc/systemd/system/blackbox-shutdown.service"
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
	was := readBefore(config.DefaultPath(), config.DefaultDataDir())
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
	if err := setupLAN(opt, data, logf); err != nil {
		return err
	}

	if err := writeUnits(dst, cfg); err != nil {
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
	logf("Scheduled:           blackbox.timer — collects %s as root; %s", EveryText(opt.CollectEvery), scheduleWhat(opt))
	recordSetup(cfgPath, data, was, opt.Version, logf)
	return nil
}

// Uninstall disables the timer and removes the unit files. Reports and
// collected data are kept.
func Uninstall(logf func(string, ...any)) error {
	if os.Geteuid() != 0 {
		return errors.New("uninstall must be run as root")
	}
	recordRemoval(logf)
	exec.Command("systemctl", "disable", "--now", "blackbox.timer").Run()
	exec.Command("systemctl", "disable", "blackbox-shutdown.service").Run()
	for _, f := range []string{timerFile, serviceFile, shutdownFile} {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	removeSendTo(logf)
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
	if err := writeUnits(ProgramPath(), cfg); err != nil {
		return err
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %v: %s", err, strings.TrimSpace(string(out)))
	}
	logf("Updated blackbox.service so it may write to %s.", cfg.ReportsDir())
	return nil
}

// writeUnits writes the service unit and, on a computer that sends to a
// collector, the unit that sends before shutdown (enabled so it runs at
// the next shutdown; removed on other computers).
func writeUnits(exe string, cfg *config.Config) error {
	if err := os.WriteFile(serviceFile, []byte(serviceFor(exe, cfg)), 0o644); err != nil {
		return err
	}
	if cfg.SendTo == "" {
		if _, err := os.Stat(shutdownFile); err == nil {
			exec.Command("systemctl", "disable", "--now", "blackbox-shutdown.service").Run()
			os.Remove(shutdownFile)
		}
		return nil
	}
	if err := os.WriteFile(shutdownFile, []byte(shutdownFor(exe, cfg)), 0o644); err != nil {
		return err
	}
	exec.Command("systemctl", "daemon-reload").Run()
	if out, err := exec.Command("systemctl", "enable", "--now", "blackbox-shutdown.service").CombinedOutput(); err != nil {
		return fmt.Errorf("enable blackbox-shutdown.service: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// serviceFor is the service unit for these settings.
func serviceFor(exe string, cfg *config.Config) string {
	mount, writable := unitPaths(cfg)
	return systemdService(exe, mount, writable...)
}

// shutdownFor is the send-before-shutdown unit for these settings.
func shutdownFor(exe string, cfg *config.Config) string {
	mount, writable := unitPaths(cfg)
	return systemdShutdownService(exe, mount, writable...)
}

// unitPaths are the share mount unit (if any) and the folders the units
// may write to.
func unitPaths(cfg *config.Config) (mount string, writable []string) {
	writable = []string{cfg.DataDir, cfg.ReportsDir()}
	switch {
	case config.IsShare(cfg.SendTo):
		mount = mountUnitName() // mounted inside the data folder
	case cfg.SendTo != "":
		writable = append(writable, "-"+cfg.SendTo)
	}
	if cfg.Inbox != "" {
		writable = append(writable, "-"+cfg.Inbox)
	}
	return mount, writable
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

// The status icon is Windows only.

// TrayWanted is always false here.
func TrayWanted() bool { return false }

// StartTray is Windows only.
func StartTray() error { return nil }

// QuitTrays is Windows only.
func QuitTrays() {}

// RemoveOld is Windows only.
func RemoveOld() {}

// InstalledVersion is only used by the Windows setup window.
func InstalledVersion() string { return "" }
