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
  blackbox install               Set up (or change) scheduled collection and reporting; asks each setting
  blackbox config                Show settings; "blackbox config set report_dir D:\Reports" changes one
  blackbox status                Show what this computer does, when it last collected, and what is waiting
  blackbox run                   Collect new events; send them or produce a report if one is due (what the schedule runs)
  blackbox send                  Collect and send to the collector now (e.g. before shutting down a VM)
  blackbox systems               List the computers whose events this collector reports on
  blackbox systems remove NAME   Stop listing a retired computer
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
	case "config":
		err = cmdConfig(args)
	case "status":
		err = cmdStatus(args)
	case "send":
		err = cmdSend(args)
	case "systems":
		err = cmdSystems(args)
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
	fs.StringVar(&c.configPath, "config", config.DefaultPath(), "settings file (\"none\" for the built-in defaults)")
}

func (c *common) load() (*config.Config, error) {
	// Without a settings file the defaults are used, but a file named on
	// the command line must exist: a typing mistake should not silently
	// run with different settings.
	if c.configPath == "none" {
		return config.Default(), nil
	}
	if c.configPath != config.DefaultPath() {
		if _, err := os.Stat(c.configPath); err != nil {
			return nil, fmt.Errorf("settings file %s: %w", c.configPath, err)
		}
	}
	return config.Load(c.configPath)
}

func newApp(cfg *config.Config, logf func(string, ...any)) *app.App {
	return &app.App{Cfg: cfg, Version: version, Logf: logf}
}

func cmdInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: blackbox install [options]

Run with no options to be asked each setting (current settings are offered
as defaults when Blackbox is already installed). Options are for scripted
or unattended installs; any setting not given keeps its current value.

`)
		fs.PrintDefaults()
		fmt.Fprint(fs.Output(), `
The share password for --share-user is read from the BLACKBOX_SHARE_PASSWORD
environment variable (so it is not shown in the process list).
`)
	}
	site := fs.String("site", "", "site or system name shown on reports (\"-\" clears it)")
	every := fs.String("report-every", "", "how often to produce a report: daily, weekly or monthly")
	reportDir := fs.String("report-dir", "", "folder for reports (\"default\" for the standard location)")
	collectEvery := fs.Duration("collect-every", 0, "how often to collect events: 1h, 30m or 15m")
	sendTo := fs.String("send-to", "", "send events to this collector inbox (a share or folder; \"none\" to stop sending)")
	shareUser := fs.String("share-user", "", "account on the collector for --send-to (\"-\" for none)")
	inbox := fs.String("inbox", "", "make this computer a collector that receives in this folder (\"none\" to stop)")
	shareInbox := fs.Bool("share-inbox", false, "Windows collector: share the inbox on the network as "+install.ShareName)
	var writers listFlag
	fs.Var(&writers, "inbox-writer", "Windows collector: an account allowed to deliver to the inbox, e.g. the user who runs VirtualBox (repeatable)")
	yes := fs.Bool("yes", false, "do not ask questions; use the options given and current or default settings")
	noReport := fs.Bool("no-first-report", false, "do not produce a report (or send) straight away")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := install.RequireAdmin(); err != nil {
		return err
	}

	// Current settings (or defaults on a first install) are the starting point.
	cur, err := config.Load(config.DefaultPath())
	if err != nil {
		return fmt.Errorf("%w\n(fix or remove the file, then run install again)", err)
	}
	_, statErr := os.Stat(config.DefaultPath())
	reinstall := statErr == nil
	ans := install.Answers{Site: cur.SiteName, ReportEvery: cur.ReportEvery, ReportDir: cur.ReportDir, CollectEvery: cur.CollectEvery,
		SendTo: cur.SendTo, ShareUser: cur.ShareUser, Inbox: cur.Inbox, ShareInbox: install.InboxShared()}
	defaultReports := filepath.Join(config.DefaultDataDir(), "reports")

	given := 0
	fs.Visit(func(f *flag.Flag) {
		if f.Name != "no-first-report" && f.Name != "yes" {
			given++
		}
	})
	if given == 0 && !*yes && install.IsTerminal(os.Stdin) {
		ans, err = install.Wizard(os.Stdin, os.Stdout, ans, defaultReports, reinstall)
		if err != nil {
			return err
		}
		fmt.Println()
	} else {
		if *site == "-" {
			ans.Site = ""
		} else if *site != "" {
			ans.Site = *site
		}
		if *every != "" {
			ans.ReportEvery = strings.ToLower(*every)
		}
		switch *reportDir {
		case "":
		case "default", defaultReports:
			ans.ReportDir = ""
		default:
			ans.ReportDir = *reportDir
		}
		if *collectEvery != 0 {
			ans.CollectEvery = *collectEvery
		}
		switch *sendTo {
		case "":
		case "none":
			ans.SendTo, ans.ShareUser = "", ""
		default:
			ans.SendTo = *sendTo
		}
		switch *shareUser {
		case "":
		case "-":
			ans.ShareUser = ""
		default:
			ans.ShareUser = *shareUser
		}
		ans.SharePassword = os.Getenv("BLACKBOX_SHARE_PASSWORD")
		switch *inbox {
		case "":
		case "none":
			ans.Inbox, ans.ShareInbox = "", false
		default:
			ans.Inbox = *inbox
		}
		if *shareInbox {
			ans.ShareInbox = true
		}
		ans.InboxWriters = writers
	}
	ans.Role = install.RoleOf(ans.SendTo, ans.Inbox)
	if err := validateInstall(ans); err != nil {
		return err
	}

	fmt.Println("Installing Blackbox", version)
	err = install.Install(install.Options{Answers: ans, Version: version, Logf: printf})
	if err != nil {
		return err
	}

	fmt.Println("\nChecking audit settings against the DISA STIG (nothing will be changed)...")
	printChecks(check.Run(), false)

	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		return err
	}
	a := newApp(cfg, printf)
	switch {
	case !cfg.MakesReports():
		if *noReport {
			fmt.Println("\nDone. Events will be collected and sent at the next scheduled run.")
			break
		}
		fmt.Println("\nCollecting events and sending them to the collector (the first run reads the whole log and can take a few minutes)...")
		r, err := a.SendNow()
		if err != nil {
			fmt.Printf("\nDone, but the collector could not be reached yet: %v\n", err)
			fmt.Printf("The events are kept safely on this computer (%d batch%s waiting) and are sent at the next scheduled run that can reach it.\n", r.Waiting, map[bool]string{true: "es"}[r.Waiting != 1])
			fmt.Println("Check with: blackbox status")
		} else {
			fmt.Printf("\nDone. Sent %d batch%s to %s.\n", r.Delivered, map[bool]string{true: "es"}[r.Delivered != 1], cfg.SendTo)
			fmt.Println("This computer's events will appear in the collector's reports.")
		}
	case *noReport:
		fmt.Println("\nDone. The first report will be produced at the next scheduled run.")
		fmt.Printf("Reports will be saved in %s\n", cfg.ReportsDir())
	default:
		fmt.Println("\nCollecting events and producing the first report (the first run reads the whole log and can take a few minutes)...")
		dir, err := a.ReportNow(true)
		if err != nil {
			return err
		}
		fmt.Printf("\nDone. First report: %s\n", filepath.Join(dir, "report.html"))
		fmt.Printf("All reports:        %s\n", filepath.Join(a.ReportsDir(), "index.html"))
	}
	if cfg.Inbox != "" {
		fmt.Printf("\nOther computers can now send to this collector's inbox: %s\n", cfg.Inbox)
		fmt.Println("Their events appear in reports after their first collection. See: blackbox status")
	}
	fmt.Println("\nTo change settings later, run the installer again (it shows the current settings),")
	fmt.Println("or use: blackbox config set <setting> <value>")
	return nil
}

func validateInstall(a install.Answers) error {
	switch a.ReportEvery {
	case "daily", "weekly", "monthly":
	default:
		return fmt.Errorf("report schedule must be daily, weekly or monthly (got %q)", a.ReportEvery)
	}
	d := a.CollectEvery
	if d < 5*time.Minute || d > 24*time.Hour || d%time.Minute != 0 {
		return fmt.Errorf("collection interval must be whole minutes between 5m and 24h (got %s)", d)
	}
	if runtime.GOOS == "linux" && time.Hour%d != 0 && (d%time.Hour != 0 || (24*time.Hour)%d != 0) {
		return fmt.Errorf("collection interval must divide an hour or a day evenly on Linux (e.g. 15m, 30m, 1h, 2h)")
	}
	if a.ReportDir != "" && !config.IsAbs(a.ReportDir) {
		return fmt.Errorf("report folder must be a full path (got %q)", a.ReportDir)
	}
	if a.SendTo != "" && !config.IsAbs(a.SendTo) && !config.IsShare(a.SendTo) {
		return fmt.Errorf("--send-to must be a full path or a share (got %q)", a.SendTo)
	}
	if a.Inbox != "" && (!config.IsAbs(a.Inbox) || config.IsShare(a.Inbox)) {
		return fmt.Errorf("--inbox must be a full path to a folder on this computer (got %q)", a.Inbox)
	}
	if a.ShareUser != "" && a.SharePassword == "" && runtime.GOOS == "linux" && config.IsShare(a.SendTo) {
		if _, err := os.Stat("/etc/blackbox/share.cred"); err != nil {
			return fmt.Errorf("set BLACKBOX_SHARE_PASSWORD to the password for %s", a.ShareUser)
		}
	}
	return nil
}

// cmdConfig shows or changes settings after installation.
func cmdConfig(args []string) error {
	path := config.DefaultPath()
	if len(args) == 0 || args[0] == "show" {
		cfg, err := config.Load(path)
		if err != nil {
			return err
		}
		src := path
		if cfg.Path == "" {
			src += " (not found: showing defaults)"
		}
		dir := cfg.ReportsDir()
		if cfg.ReportDir == "" {
			dir += " (default)"
		}
		fmt.Printf("Settings file:   %s\n\n", src)
		fmt.Printf("  site_name          %s\n", cfg.SiteName)
		fmt.Printf("  report_every       %s\n", cfg.ReportEvery)
		fmt.Printf("  report_dir         %s\n", dir)
		fmt.Printf("  collect_every      %s   (change by running the installer again)\n", config.FormatDuration(cfg.CollectEvery))
		fmt.Printf("  retention_days     %d%s\n", cfg.RetentionDays, map[bool]string{true: "   (keep forever)"}[cfg.RetentionDays == 0])
		fmt.Printf("  exclude_users      %s\n", strings.Join(cfg.ExcludeUsers, ", "))
		fmt.Printf("  exclude_processes  %s\n", strings.Join(cfg.ExcludeProcesses, ", "))
		fmt.Printf("\n  role               %s\n", cfg.Role())
		fmt.Printf("  send_to            %s\n", cfg.SendTo)
		fmt.Printf("  share_user         %s\n", cfg.ShareUser)
		fmt.Printf("  inbox              %s\n", cfg.Inbox)
		fmt.Printf("\nChange a setting:  blackbox config set <setting> <value>\n")
		return nil
	}
	if args[0] != "set" || len(args) < 2 {
		return fmt.Errorf("usage: blackbox config                     (show settings)\n       blackbox config set <setting> <value>\nsettings: %s", strings.Join(config.Settable, ", "))
	}
	key, value := strings.ToLower(args[1]), strings.Join(args[2:], " ")
	if err := install.RequireAdmin(); err != nil {
		return err
	}
	if key == "report_dir" {
		if value == "default" || value == filepath.Join(config.DefaultDataDir(), "reports") {
			value = ""
		}
		if err := install.SetReportDir(path, value, printf); err != nil {
			return err
		}
		cfg, _ := config.Load(path)
		fmt.Printf("Reports will now be saved in %s (existing reports were not moved).\n", cfg.ReportsDir())
		return nil
	}
	if value == "none" && (key == "send_to" || key == "inbox" || key == "share_user") {
		value = ""
	}
	if err := config.SetValue(path, key, value); err != nil {
		return err
	}
	if key == "send_to" || key == "inbox" || key == "share_user" {
		if err := install.ApplyLAN(path, printf); err != nil {
			return err
		}
	}
	fmt.Printf("Saved %s = %s. It takes effect at the next scheduled run.\n", key, value)
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	var c common
	c.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := c.load()
	if err != nil {
		return err
	}
	return newApp(cfg, nil).Status(os.Stdout)
}

func cmdSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
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
	r, err := newApp(cfg, logf).SendNow()
	if err != nil {
		return err
	}
	fmt.Printf("Sent %d batch%s to %s. Nothing is waiting.\n", r.Delivered, map[bool]string{true: "es"}[r.Delivered != 1], cfg.SendTo)
	return nil
}

func cmdSystems(args []string) error {
	fs := flag.NewFlagSet("systems", flag.ContinueOnError)
	var c common
	c.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := c.load()
	if err != nil {
		return err
	}
	a := newApp(cfg, nil)
	rest := fs.Args()
	switch {
	case len(rest) == 0:
		return a.Systems(os.Stdout)
	case len(rest) == 2 && (rest[0] == "remove" || rest[0] == "forget"):
		if err := install.RequireAdmin(); err != nil {
			return err
		}
		if err := a.RemoveSystem(rest[1]); err != nil {
			return err
		}
		fmt.Printf("%s will no longer be listed or reported as silent. Its events stay in earlier reports.\nIf it sends again, it will be listed again.\n", rest[1])
		return nil
	}
	return errors.New("usage: blackbox systems              (list)\n       blackbox systems remove NAME  (stop listing a retired computer)")
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
