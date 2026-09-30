package install

import (
	"bufio"
	"bytes"
	"errors"
	"path/filepath"
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

// runWizard feeds scripted answers (one per line) to the wizard.
func runWizard(t *testing.T, input string, cur Answers, existing map[string]bool, reinstall bool) (Answers, string, error) {
	t.Helper()
	var out bytes.Buffer
	w := &wizard{in: bufio.NewReader(strings.NewReader(input)), out: &out,
		dirExists: func(p string) (bool, error) { return existing[p], nil },
		dirWritable: func(p string) error {
			if strings.Contains(p, "readonly") {
				return errors.New("access is denied")
			}
			return nil
		}}
	a, err := w.run(cur, abs("/var/lib/blackbox/reports"), reinstall)
	return a, out.String(), err
}

func TestWizardDefaults(t *testing.T) {
	// Enter on every question, then Enter to confirm.
	a, out, err := runWizard(t, "\n\n\n\n\n", Answers{}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	want := Answers{ReportEvery: "weekly", CollectEvery: time.Hour}
	if a != want {
		t.Errorf("got %+v, want %+v", a, want)
	}
	for _, s := range []string{"1. Site or system name", "2. How often should a report", "3. Where should reports be saved",
		"4. How often should events be collected", "Summary", "Install these settings?"} {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q", s)
		}
	}
}

func TestWizardAnswersAndRetries(t *testing.T) {
	input := strings.Join([]string{
		"Lab 3",  // site
		"9", "1", // invalid choice is asked again, then daily
		"reports",               // relative path: asked again
		abs("/srv/readonly"),    // exists but not writable: asked again
		abs("/srv/new-reports"), // does not exist…
		"y",                     // …create it
		"3",                     // every 15 minutes
		"",                      // confirm
	}, "\n") + "\n"
	a, out, err := runWizard(t, input, Answers{}, map[string]bool{abs("/srv/readonly"): true}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := Answers{Site: "Lab 3", ReportEvery: "daily", ReportDir: abs("/srv/new-reports"), CollectEvery: 15 * time.Minute}
	if a != want {
		t.Errorf("got %+v, want %+v", a, want)
	}
	for _, s := range []string{"Please enter a number from 1 to 3", "Please enter a full path", "cannot write to that folder", "does not exist yet"} {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q", s)
		}
	}
}

func TestWizardReinstallKeepsCurrentSettings(t *testing.T) {
	cur := Answers{Site: "Lab 3", ReportEvery: "monthly", ReportDir: abs("/srv/locked"), CollectEvery: 2 * time.Hour}
	a, out, err := runWizard(t, "\n\n\n\n\n", cur, map[string]bool{abs("/srv/locked"): true}, true)
	if err != nil {
		t.Fatal(err)
	}
	if a != cur {
		t.Errorf("re-install with Enter everywhere changed settings: %+v", a)
	}
	if !strings.Contains(out, "(current setting)") || !strings.Contains(out, "Apply these settings?") {
		t.Errorf("re-install prompts wrong:\n%s", out)
	}
}

func TestWizardDefaultFolderAndClearSite(t *testing.T) {
	cur := Answers{Site: "Old", ReportEvery: "weekly", ReportDir: abs("/srv/locked"), CollectEvery: time.Hour}
	a, _, err := runWizard(t, "-\n\n"+abs("/var/lib/blackbox/reports")+"\n\n\n", cur, map[string]bool{abs("/srv/locked"): true}, true)
	if err != nil {
		t.Fatal(err)
	}
	if a.Site != "" || a.ReportDir != "" {
		t.Errorf("site should be cleared and folder back to default: %+v", a)
	}
}

func TestWizardCancel(t *testing.T) {
	if _, _, err := runWizard(t, "\n\n\n\nn\n", Answers{}, nil, false); !errors.Is(err, ErrCancelled) {
		t.Errorf("answering no should cancel, got %v", err)
	}
	if _, _, err := runWizard(t, "Lab", Answers{}, nil, false); !errors.Is(err, ErrCancelled) {
		t.Errorf("input ending early should cancel, got %v", err)
	}
}
