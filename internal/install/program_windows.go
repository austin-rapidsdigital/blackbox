//go:build windows

package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/casea1/blackbox/internal/hidden"
	"github.com/casea1/blackbox/internal/winexe"
)

// WindowedPath is the windowed copy of the program: the setup window and
// the status icon run from it, so Windows opens no console for them.
func WindowedPath() string { return filepath.Join(filepath.Dir(ProgramPath()), "blackboxw.exe") }

// placePrograms installs blackbox.exe (console) and blackboxw.exe
// (windowed) from the running program, whatever its name.
//
// A running program can't be overwritten but can be renamed, so each file
// in place is renamed to .old first: a collection in progress or an open
// status icon never blocks an upgrade. The .old files are kept until the
// new program has been checked (see checkPrograms), and deleted at the
// next install.
func placePrograms(self string) error {
	src, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	RemoveOld()
	for _, p := range []struct {
		path     string
		windowed bool
	}{{ProgramPath(), false}, {WindowedPath(), true}} {
		b, err := winexe.SetSubsystem(src, p.windowed)
		if err != nil {
			return err
		}
		tmp := p.path + ".new"
		if err := os.WriteFile(tmp, b, 0o755); err != nil {
			return err
		}
		if _, err := os.Stat(p.path); err == nil {
			if err := os.Rename(p.path, oldName(p.path)); err != nil {
				os.Remove(tmp)
				return err
			}
		}
		if err := os.Rename(tmp, p.path); err != nil {
			return err
		}
	}
	return nil
}

// oldName is where a replaced program waits until the new one is checked.
// A previous .old still in use (an icon that hasn't restarted yet) is
// left alone and the next free name is used.
func oldName(p string) string {
	for i := 0; ; i++ {
		n := p + ".old"
		if i > 0 {
			n = fmt.Sprintf("%s.old%d", p, i)
		}
		if _, err := os.Stat(n); os.IsNotExist(err) {
			return n
		}
	}
}

// RemoveOld deletes replaced programs that are no longer running.
func RemoveOld() {
	list, _ := filepath.Glob(filepath.Join(filepath.Dir(ProgramPath()), "*.exe.old*"))
	for _, f := range list {
		os.Remove(f)
	}
}

// checkPrograms runs the installed program and confirms it is the version
// just installed. If it isn't, the previous program is put back.
func checkPrograms(version string) error {
	out, err := hidden.Command(ProgramPath(), "version").Output()
	got := strings.TrimSpace(string(out))
	if err == nil && got == "blackbox "+version {
		return nil
	}
	if err == nil {
		err = fmt.Errorf("it answered %q", got)
	}
	restored := false
	for _, p := range []string{ProgramPath(), WindowedPath()} {
		if _, e := os.Stat(p + ".old"); e == nil {
			os.Remove(p)
			restored = os.Rename(p+".old", p) == nil
		}
	}
	if restored {
		return fmt.Errorf("the new program did not start (%v); the previous version was put back", err)
	}
	return fmt.Errorf("the new program did not start: %v", err)
}

// TrayWanted says whether the status icon is on: it is when its task
// exists, and by default when upgrading from a version without it. It is
// off only when it was turned off.
func TrayWanted() bool {
	if hidden.Command("schtasks.exe", "/Query", "/TN", TrayTaskName).Run() == nil {
		return true
	}
	_, err := os.Stat(WindowedPath())
	return err != nil
}

// setupTray registers or removes the task that starts the status icon.
func setupTray(on bool, logf func(string, ...any)) error {
	if !on {
		if hidden.Command("schtasks.exe", "/Query", "/TN", TrayTaskName).Run() == nil {
			hidden.Command("schtasks.exe", "/Delete", "/TN", TrayTaskName, "/F").Run()
			logf("Status icon:         removed")
		}
		QuitTrays()
		return nil
	}
	tmp := filepath.Join(os.TempDir(), "blackbox-tray-task.xml")
	if err := os.WriteFile(tmp, utf16LE(trayTaskXML(WindowedPath())), 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if out, err := hidden.Command("schtasks.exe", "/Create", "/TN", TrayTaskName, "/XML", tmp, "/F").CombinedOutput(); err != nil {
		return fmt.Errorf("create status icon task: %v: %s", err, strings.TrimSpace(string(out)))
	}
	logf("Status icon:         shown to administrators when they log on (task \"%s\")", TrayTaskName)
	return nil
}

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procCreateEventW = kernel32.NewProc("CreateEventW")
	procSetEvent     = kernel32.NewProc("SetEvent")
)

// QuitTrays asks every running status icon to close, and gives them a
// moment to do so.
func QuitTrays() {
	name, _ := syscall.UTF16PtrFromString(TrayQuitEvent)
	h, _, _ := procCreateEventW.Call(0, 1, 0, uintptr(unsafe.Pointer(name)))
	if h == 0 {
		return
	}
	procSetEvent.Call(h)
	time.Sleep(1500 * time.Millisecond)
	syscall.CloseHandle(syscall.Handle(h))
}

// StartTray starts the status icon for the person running setup.
func StartTray() error {
	cmd := hidden.Command(WindowedPath(), "tray")
	cmd.Dir = filepath.Dir(WindowedPath())
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// IsAdmin reports whether this process has full administrator rights.
func IsAdmin() bool { return isAdmin() }

// InstalledVersion is the version of the installed program, or "".
func InstalledVersion() string {
	if _, err := os.Stat(ProgramPath()); err != nil {
		return ""
	}
	out, err := hidden.Command(ProgramPath(), "version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(strings.TrimSpace(string(out)), "blackbox ")
}
