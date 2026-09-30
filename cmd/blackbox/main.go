// Command blackbox collects Windows (and soon Linux) audit logs and
// produces plain-English audit reports for air-gapped systems.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/app"
	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/install"
	"github.com/casea1/blackbox/internal/report"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

const usage = `Blackbox — audit log review for air-gapped systems

Usage:
  blackbox install [options]     Set up scheduled collection and reporting (run as administrator)
  blackbox run                   Collect new events; produce a report if one is due (what the schedule runs)
  blackbox report [options]      Collect and produce a report now
  blackbox report --xml FILE     Produce a report from exported Windows event logs (any OS)
  blackbox report --audit FILE --syslog FILE
                                 Produce a report from copied Linux logs (any OS)
  blackbox check                 Check audit settings against the DISA STIG (report only; changes nothing)
  blackbox check --audit-rules   Linux: print the recommended auditd rules file
  blackbox verify FOLDER         Confirm a report has not been altered since it was produced
  blackbox uninstall             Remove the scheduled task (keeps reports and data)
  blackbox version               Show the version

Run "blackbox <command> -h" for a command's options.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "install":
		err = cmdInstall(args)
	case "run":
		err = cmdRun(args)
	case "report":
		err = cmdReport(args)
	case "collect":
		err = cmdCollect(args)
	case "check":
		err = cmdCheck(args)
	case "verify":
		err = cmdVerify(args)
	case "uninstall":
		err = install.Uninstall(printf)
	case "version", "--version", "-v":
		fmt.Println("blackbox", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "blackbox:", err)
		os.Exit(1)
	}
}

func printf(format string, args ...any) { fmt.Printf(format+"\n", args...) }

// common flags shared by commands that read the config.
type common struct {
	configPath string
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.configPath, "config", config.DefaultPath(), "configuration file")
}

func (c *common) load() (*config.Config, error) {
	return config.Load(c.configPath)
}

func newApp(cfg *config.Config, logf func(string, ...any)) *app.App {
	return &app.App{Cfg: cfg, Version: version, Logf: logf}
}

func cmdInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	site := fs.String("site", "", "site or system name shown on reports")
	every := fs.String("report-every", "weekly", "how often to produce a report: daily, weekly or monthly")
	collectEvery := fs.Duration("collect-every", time.Hour, "how often to collect events (e.g. 1h, 30m, 15m)")
	noReport := fs.Bool("no-first-report", false, "do not produce a report straight away")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch *every {
	case "daily", "weekly", "monthly":
	default:
		return fmt.Errorf("--report-every must be daily, weekly or monthly")
	}
	if *collectEvery < 5*time.Minute || *collectEvery > 24*time.Hour || *collectEvery%time.Minute != 0 {
		return fmt.Errorf("--collect-every must be whole minutes between 5m and 24h")
	}
	if runtime.GOOS == "linux" && time.Hour%*collectEvery != 0 && (*collectEvery%time.Hour != 0 || (24*time.Hour)%*collectEvery != 0) {
		return fmt.Errorf("--collect-every must divide an hour or a day evenly on Linux (e.g. 15m, 30m, 1h, 2h)")
	}
	fmt.Println("Installing Blackbox", version)
	err := install.Install(install.Options{Site: *site,
		ReportEvery: *every, CollectEvery: *collectEvery, Logf: printf})
	if err != nil {
		return err
	}

	fmt.Println("\nChecking audit settings against the DISA STIG (nothing will be changed)...")
	printChecks(check.Run(), false)

	if *noReport {
		fmt.Println("\nDone. The first report will be produced at the next scheduled run.")
		return nil
	}
	fmt.Println("\nCollecting events and producing the first report (the first run reads the whole log and can take a few minutes)...")
	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		return err
	}
	a := newApp(cfg, printf)
	dir, err := a.ReportNow(true)
	if err != nil {
		return err
	}
	fmt.Printf("\nDone. First report: %s\n", filepath.Join(dir, "report.html"))
	fmt.Printf("All reports:        %s\n", filepath.Join(a.ReportsDir(), "index.html"))
	return nil
}

// cmdRun is what the scheduled task runs. Output goes to a log file in
// the data folder as well as the console.
func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var c common
	c.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := c.load()
	if err != nil {
		return err
	}
	logf, closeLog := openLog(cfg.DataDir)
	defer closeLog()
	a := newApp(cfg, logf)
	logf("run started (blackbox %s)", version)
	dir, err := a.Scheduled()
	if err != nil {
		logf("run failed: %v", err)
		return err
	}
	if dir != "" {
		logf("report written: %s", filepath.Join(dir, "report.html"))
	}
	logf("run finished")
	return nil
}

func cmdCollect(args []string) error {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	var c common
	c.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := c.load()
	if err != nil {
		return err
	}
	run, err := newApp(cfg, nil).Collect()
	if err != nil {
		return err
	}
	fmt.Print(app.Describe(run))
	return nil
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	var c common
	c.register(fs)
	var in app.Inputs
	fs.Var((*listFlag)(&in.XML), "xml", "Windows: exported event XML (wevtutil qe … /f:xml, or Event Viewer \"Save as XML\"); repeatable")
	fs.Var((*listFlag)(&in.EVTX), "evtx", "Windows: exported .evtx file (read on Windows only); repeatable")
	fs.Var((*listFlag)(&in.Audit), "audit", "Linux: auditd log (audit.log, rotated copies, .gz); repeatable")
	fs.Var((*listFlag)(&in.Syslog), "syslog", "Linux: syslog/messages/kern.log (USB), or auth.log/secure when there is no audit log; repeatable")
	fs.StringVar(&in.Host, "host", "", "Linux: host name to show, if the logs do not include it")
	fs.StringVar(&in.Passwd, "passwd", "", "Linux: copy of /etc/passwd, to show names instead of user IDs")
	out := fs.String("out", "", "output folder for reports from files (default: ./blackbox-report-<time>)")
	preview := fs.Bool("preview", false, "produce a report without affecting the scheduled report sequence")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := c.load()
	if err != nil {
		return err
	}
	a := newApp(cfg, printf)
	var dir string
	if !in.Empty() {
		dir, err = a.ReportFromFiles(in, *out)
	} else {
		dir, err = a.ReportNow(!*preview)
	}
	if err != nil {
		return err
	}
	fmt.Println("Report written:", filepath.Join(dir, "report.html"))
	return nil
}

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	all := fs.Bool("all", false, "also list settings that pass")
	rules := fs.Bool("audit-rules", false, "Linux: print Blackbox's recommended auditd rules file and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rules {
		fmt.Print(check.AuditRules)
		return nil
	}
	if !check.Supported {
		return errors.New("the audit settings check runs on Windows and Linux")
	}
	rs := check.Run()
	printChecks(rs, *all)
	if _, fail, _ := check.Summary(rs); fail > 0 {
		os.Exit(3) // lets scripts detect non-compliance
	}
	return nil
}

func printChecks(rs []check.Result, all bool) {
	pass, fail, warn := check.Summary(rs)
	for _, r := range rs {
		if r.Status == check.Pass && !all {
			continue
		}
		fmt.Printf("  [%-5s] %s: %s — have %s, need %s\n", strings.ToUpper(string(r.Status)), r.Area, r.Item, r.Have, r.Want)
		if r.Affects != "" && r.Status != check.Pass {
			fmt.Printf("           Affects: %s\n", r.Affects)
		}
		if r.Fix != "" {
			fmt.Printf("           Fix:     %s\n", r.Fix)
		}
	}
	fmt.Printf("  %d settings pass, %d need attention", pass, fail)
	if warn > 0 {
		fmt.Printf(", %d warnings", warn)
	}
	fmt.Println(".")
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("usage: blackbox verify <report folder> [more folders…]")
	}
	bad := false
	for _, dir := range fs.Args() {
		problems, err := report.Verify(dir)
		switch {
		case err != nil:
			fmt.Printf("%s: cannot verify: %v\n", dir, err)
			bad = true
		case len(problems) > 0:
			fmt.Printf("%s: FAILED\n", dir)
			for _, p := range problems {
				fmt.Println("   ", p)
			}
			bad = true
		default:
			fmt.Printf("%s: OK — all files match the manifest\n", dir)
		}
	}
	if bad {
		os.Exit(1)
	}
	return nil
}

// openLog appends to <data>/blackbox.log (rotated at 5 MB) and echoes to
// the console.
func openLog(dataDir string) (func(string, ...any), func()) {
	os.MkdirAll(dataDir, 0o750)
	p := filepath.Join(dataDir, "blackbox.log")
	if fi, err := os.Stat(p); err == nil && fi.Size() > 5<<20 {
		os.Rename(p, p+".1")
	}
	var w io.Writer = os.Stdout
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err == nil {
		w = io.MultiWriter(os.Stdout, f)
	}
	logf := func(format string, args ...any) {
		fmt.Fprintf(w, "%s %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
	}
	return logf, func() {
		if f != nil {
			f.Close()
		}
	}
}
