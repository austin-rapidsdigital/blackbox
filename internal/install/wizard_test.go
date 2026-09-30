package install

import (
	"bufio"
	"bytes"
	"errors"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// abs turns a slash path into an absolute path for this OS
// (/srv/x stays /srv/x on Linux and becomes D:\srv\x on Windows).
func abs(p string) string {
	if runtime.GOOS == "windows" {
		return "D:" + filepath.FromSlash(p)
	}
	return p
}

// fakeEnv describes the computer the wizard runs on in a test.
type fakeEnv struct {
	existing  map[string]bool   // folders that exist
	inboxes   []string          // collector inboxes found
	reachable map[string]string // send_to → password that works ("" = any)
	windows   bool
}

// runWizard feeds scripted answers (one per line) to the wizard.
func runWizard(t *testing.T, input string, cur Answers, env fakeEnv, reinstall bool) (Answers, string, error) {
	t.Helper()
	var out bytes.Buffer
	in := bufio.NewReader(strings.NewReader(input))
	w := &wizard{in: in, out: &out,
		dirExists: func(p string) (bool, error) { return env.existing[p], nil },
		dirWritable: func(p string) error {
			if strings.Contains(p, "readonly") {
				return errors.New("access is denied")
			}
			return nil
		},
		password: func(prompt string) (string, error) {
			out.WriteString(prompt)
			return readPasswordPlain(in)
		},
		findInboxes: func() []string { return env.inboxes },
		tryInbox: func(sendTo, user, pw string) error {
			want, ok := env.reachable[sendTo]
			if !ok || (want != "" && pw != want) {
				return errors.New("could not connect")
			}
			return nil
		},
		defaultInbox: abs("/srv/blackbox-inbox"),
		isWindows:    env.windows,
	}
	a, err := w.run(cur, abs("/var/lib/blackbox/reports"), reinstall)
	return a, out.String(), err
}

func readPasswordPlain(r *bufio.Reader) (string, error) {
	s, err := r.ReadString('\n')
	if err != nil && s == "" {
		return "", ErrCancelled
	}
	return strings.TrimSpace(s), nil
}

func lines(l ...string) string { return strings.Join(l, "\n") + "\n" }

func TestWizardDefaults(t *testing.T) {
	// Enter on every question, then Enter to confirm.
	a, out, err := runWizard(t, lines("", "", "", "", "", ""), Answers{}, fakeEnv{}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := Answers{Role: RoleStandalone, ReportEvery: "weekly", CollectEvery: time.Hour}
	if !reflect.DeepEqual(a, want) {
		t.Errorf("got %+v, want %+v", a, want)
	}
	for _, s := range []string{"1. How will this computer's audit events be reviewed?", "2. Site or system name", "3. How often should a report",
		"4. Where should reports be saved", "5. How often should events be collected", "Summary", "Install these settings?"} {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q", s)
		}
	}
}

func TestWizardAnswersAndRetries(t *testing.T) {
	input := lines(
		"1",      // standalone
		"Lab 3",  // site
		"9", "1", // invalid choice is asked again, then daily
		"reports",               // relative path: asked again
		abs("/srv/readonly"),    // exists but not writable: asked again
		abs("/srv/new-reports"), // does not exist…
		"y",                     // …create it
		"3",                     // every 15 minutes
		"",                      // confirm
	)
	a, out, err := runWizard(t, input, Answers{}, fakeEnv{existing: map[string]bool{abs("/srv/readonly"): true}}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := Answers{Role: RoleStandalone, Site: "Lab 3", ReportEvery: "daily", ReportDir: abs("/srv/new-reports"), CollectEvery: 15 * time.Minute}
	if !reflect.DeepEqual(a, want) {
		t.Errorf("got %+v, want %+v", a, want)
	}
	for _, s := range []string{"Please enter a number from 1 to 3", "Please enter a full path", "cannot write to that folder", "does not exist yet"} {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q", s)
		}
	}
}

func TestWizardReinstallKeepsCurrentSettings(t *testing.T) {
	cur := Answers{Role: RoleStandalone, Site: "Lab 3", ReportEvery: "monthly", ReportDir: abs("/srv/locked"), CollectEvery: 2 * time.Hour}
	a, out, err := runWizard(t, lines("", "", "", "", "", ""), cur, fakeEnv{existing: map[string]bool{abs("/srv/locked"): true}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, cur) {
		t.Errorf("re-install with Enter everywhere changed settings: %+v", a)
	}
	if !strings.Contains(out, "(current setting)") || !strings.Contains(out, "Apply these settings?") {
		t.Errorf("re-install prompts wrong:\n%s", out)
	}
}

func TestWizardDefaultFolderAndClearSite(t *testing.T) {
	cur := Answers{Site: "Old", ReportEvery: "weekly", ReportDir: abs("/srv/locked"), CollectEvery: time.Hour}
	a, _, err := runWizard(t, lines("", "-", "", abs("/var/lib/blackbox/reports"), "", ""), cur, fakeEnv{existing: map[string]bool{abs("/srv/locked"): true}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if a.Site != "" || a.ReportDir != "" {
		t.Errorf("site should be cleared and folder back to default: %+v", a)
	}
}

func TestWizardCancel(t *testing.T) {
	if _, _, err := runWizard(t, lines("", "", "", "", "", "n"), Answers{}, fakeEnv{}, false); !errors.Is(err, ErrCancelled) {
		t.Errorf("answering no should cancel, got %v", err)
	}
	if _, _, err := runWizard(t, "1\nLab", Answers{}, fakeEnv{}, false); !errors.Is(err, ErrCancelled) {
		t.Errorf("input ending early should cancel, got %v", err)
	}
}

// A Linux virtual machine whose host shares the collector's inbox with it.
func TestWizardSenderFindsVirtualBoxFolder(t *testing.T) {
	env := fakeEnv{inboxes: []string{"/media/sf_BlackboxInbox"}, reachable: map[string]string{"/media/sf_BlackboxInbox": ""}}
	a, out, err := runWizard(t, lines("2", "", "", ""), Answers{}, env, false)
	if err != nil {
		t.Fatal(err)
	}
	want := Answers{Role: RoleSender, ReportEvery: "weekly", SendTo: "/media/sf_BlackboxInbox", CollectEvery: time.Hour}
	if !reflect.DeepEqual(a, want) {
		t.Errorf("got %+v, want %+v", a, want)
	}
	for _, s := range []string{"Found a collector inbox at /media/sf_BlackboxInbox", "OK, it is a Blackbox inbox", "Sends to:"} {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q", s)
		}
	}
	if strings.Contains(out, "Where should reports be saved") {
		t.Error("a sender makes no reports, so it is not asked where to save them")
	}
}

// A bare-metal Ubuntu PC sending to the LAN collector's share.
func TestWizardSenderShareWithRetry(t *testing.T) {
	share := "//COLLECTOR/BlackboxInbox"
	env := fakeEnv{reachable: map[string]string{share: "right"}}
	input := lines(
		"2",
		`\\COLLECTOR\BlackboxInbox`, "bbsend", "wrong", // Windows-style name is accepted; wrong password
		"n",                     // do not keep it: ask again
		"", "", "right", "", "", // same share and account, new password; interval; confirm
	)
	a, out, err := runWizard(t, input, Answers{}, env, false)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if a.SendTo != share || a.ShareUser != "bbsend" || a.SharePassword != "right" || a.Role != RoleSender {
		t.Errorf("got %+v", a)
	}
	if !strings.Contains(out, "not reachable") || !strings.Contains(out, "Password for bbsend") {
		t.Errorf("output:\n%s", out)
	}
	if strings.Contains(out, "right") {
		t.Error("the password must not be echoed in the summary")
	}
}

// A collector that is offline during setup can still be chosen.
func TestWizardSenderKeepsUnreachableCollector(t *testing.T) {
	a, _, err := runWizard(t, lines("2", "/media/sf_BlackboxInbox", "y", "", ""), Answers{}, fakeEnv{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if a.SendTo != "/media/sf_BlackboxInbox" {
		t.Errorf("got %+v", a)
	}
}

// The Windows PC that makes the reports, for its own VM and the LAN.
func TestWizardWindowsCollector(t *testing.T) {
	input := lines(
		"3",      // collector
		"Lab 3",  // site
		"1",      // daily
		"",       // default report folder
		"",       // default inbox…
		"y",      // …create it
		"y",      // VMs on this PC send to it
		"vmuser", // account that runs VirtualBox
		"y",      // share it on the network too
		"",       // hourly
		"",       // confirm
	)
	a, out, err := runWizard(t, input, Answers{}, fakeEnv{windows: true}, false)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want := Answers{Role: RoleCollector, Site: "Lab 3", ReportEvery: "daily", CollectEvery: time.Hour,
		Inbox: abs("/srv/blackbox-inbox"), ShareInbox: true, InboxWriters: []string{"vmuser"}}
	if !reflect.DeepEqual(a, want) {
		t.Errorf("got %+v, want %+v", a, want)
	}
	if !strings.Contains(out, "shared on the network as BlackboxInbox") || !strings.Contains(out, "Can deliver:      vmuser") {
		t.Errorf("summary:\n%s", out)
	}
}

// A LAN PC that hosts a Linux VM: receives from the VM, sends everything on.
func TestWizardRelay(t *testing.T) {
	share := `\\COLLECTOR\BlackboxInbox`
	input := lines("4", "", "y", "y", "", "n", share, "", "", "")
	a, out, err := runWizard(t, input, Answers{}, fakeEnv{windows: true, reachable: map[string]string{share: ""}}, false)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if a.Role != RoleRelay || a.Inbox == "" || a.SendTo != share || a.ShareInbox || a.ShareUser != "" {
		t.Errorf("got %+v", a)
	}
	if strings.Contains(out, "Where should reports be saved") {
		t.Error("a relay makes no reports")
	}
}

// Changing a collector back to standalone clears the LAN settings.
func TestWizardBackToStandalone(t *testing.T) {
	cur := Answers{Role: RoleCollector, Inbox: abs("/srv/blackbox-inbox"), ShareInbox: true, ReportEvery: "weekly", CollectEvery: time.Hour}
	a, _, err := runWizard(t, lines("1", "", "", "", "", ""), cur, fakeEnv{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if a.Inbox != "" || a.ShareInbox || a.Role != RoleStandalone {
		t.Errorf("got %+v", a)
	}
}
