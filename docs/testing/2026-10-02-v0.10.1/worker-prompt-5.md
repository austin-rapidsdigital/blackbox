You're working on Blackbox (github.com/casea1/blackbox). This round is a UI/UX review of 0.15.0. All three test machines were upgraded to 0.15.0, manual reports were made on an Ubuntu 26.04 standalone and a Windows 11 collector (with a Server 2025 sender), and both reports folders were opened in Chromium at 1440×900 and 1280×800. Details and evidence are in `docs/testing/2026-10-02-v0.10.1/findings.md`, section "UI/UX review", rows UI1–UI7. Only things seen on screen or confirmed in `summary.json` are listed.

Same owner decisions as before (`docs/design.md` §13): report only, no third-party dependencies (the report stays a self-contained HTML file), plain-English sentences, no sign-off section. Keep what works: Inventory, the Antivirus table, All reports with its Incomplete filter, "Manual" naming, the SCAP rule list (SC3), clickable boxes.

Same working rules: one PR per group, tests, gofmt, vet on Linux and Windows, docs in the same PR, IDs in commit messages. Include before/after screenshots in each UI PR.

## 1. Trends (UI1, the owner noticed this; do first)

Every trend treats each earlier report as one point, whatever period it covers, while the labels say weeks. On the Ubuntu test system the points are:
- the first report: 2.7 days, 1,814 privileged actions (the first run reads back through the logs);
- a daily report: 10 h, 78;
- the current manual report: 12.5 h, 42.

The result:
- **Overview trend boxes:** "42 this week · avg 946" (946 = (1814+78)/2), on an axis labelled "12 weeks ago … This week" whose points are 3 days apart.
- **What changed:** "Privileged actions: 42 this week, down 96% on the average of the last 2 reports", and "down 100%" for everything else: half a day against a multi-day average.
- **Trends page:** columns W40, W40, W41 and "This wk", where the last two are the same week.
- **All reports:** "Detections per week · Last 3 reports" has bars "W40" and "Latest". Its Latest bar (about 14 High) isn't the report the table marks LATEST (the manual one, 2 High).
- **Too little history:** with one earlier report, or one that lacked the count (the 5 Oct report's Privileged actions), a box draws nothing and has no average, with no explanation. Otherwise it's a 2-point diagonal.

Fix:
1. **Count by calendar week**, or by the site's report period if you prefer days for daily reports, using event times from the reports' data rather than one value per report. Two reports in one week are one week.
2. **Keep manual reports out of the history.** Show the current period as "so far this week (N of 7 days)", and compare it with the same elapsed share of the average, or don't compare it.
3. **The first report:** it reads back before the install. Count only whole weeks it covers, or mark it as partial and leave it out of averages.
4. **Label the x-axis with real dates or ISO weeks**, and say how many weeks are shown.
5. **Too little history:** with fewer than 2 complete weeks, say "Not enough history yet: trends start after 2 full weeks", instead of an empty box or a 2-point line. Do the same in "What changed".
6. **Tests:** a fixture with a long first report, daily reports, a manual report, and two reports in one week.

## 2. Accuracy shown on screen

- **UI2: a computer that stopped sending shows as Healthy, as a VM that was off.**
  - Ubuntu went standalone on 5 Oct 13:40 and sends nothing to the Windows 11 collector. That collector's report says:
    - "Healthy" and "Linux · Virtual machine on WIN-498EC8UMUEL";
    - Collected "off", "On 0% of the period; collected whenever it was on (0 runs)";
    - on the Overview, "Every system reporting 3/3 · VMs reported whenever they were on".
  - It isn't a VM on that server. The label seems to come from its old data having been relayed through the former collector (L14).
  - Only call something a VM when the sender says so, e.g. the VirtualBox shared-folder route.
  - A system that sent nothing for the whole period is at least "Worth a look: nothing received since <time>", even if it is a VM.
  - Inventory's "No inventory yet from ubuntu-server … from version 0.13 on" should give the real reason ("has sent nothing since 5 Oct 06:31").
- **UI4: upgrading Blackbox raises High "Possible covering of tracks".** The report's only two detections were "claude created the user account bbsend2 … 23 hours later: claude changed or deleted Blackbox's data: C:\ProgramData\Blackbox (using Blackbox-Setup-0.15.0.exe)", and the same with blackbox.conf.new. Treat Blackbox's own installer (the setup exe, matched with the self-recorded "installed/upgraded" row) as Blackbox, so its writes to the data folder are neither rows nor a second step of covering of tracks.

## 3. Layout and wording

- **UI3: Audit health's "Every system, every check" hides columns.** 12 columns sit in a panel that scrolls sideways with no visible cue. At 1440 px, Reporting and Logs intact are off-screen; at 1280 px, Log size too. Ubuntu's gaps (auditd SUSPEND) are in the hidden columns, so its visible row is all green. Give the matrix the full content width (move Gaps below it), shorten or rotate the headers, keep the System column sticky, and add a clear "more →" cue if it still scrolls. Check at 1280, 1440 and 1920.
- **UI5:** a manual report's Original logs page shows four zero tiles (0 archives, 0 KB, 0/0 hashes, 0 missing) and "This report was made without keeping the original logs", under a subtitle saying they're "saved in this report's folder". Instead, say where the originals are waiting (`archive_dir`), the period and size so far, and which scheduled report will hold them. Hide the zero tiles.
- **UI6:** All reports' Period column shows "6 – 6 Oct 2026", and "5 – 5 Oct 2026" and "4 – 4 Oct 2026" twice each. Show one date for a single day, and times for periods under a day ("5 Oct 00:00 – 06:44"), so reports can be told apart. Use the same number format everywhere ("95229 events lost" sits next to "3,130").
- **UI7 (minor):**
  - The Trends page's "After-hours admin" card is empty when `working_hours` isn't set; say "Set working_hours to see this", as the Overview tile does.
  - Inventory and Audit health wrap their header buttons under the title, while other pages keep them on the right; make them consistent.
  - Overview system tiles cut names off ("WIN-498E…", "ubuntu-ser…"); widen them or wrap, with the full name in a tooltip.
  - Audit health's "Logs too small 9" box summarises as "ubuntu-server SUSPEND +2". Either rename the box "Log size and space settings", or keep the auditd actions out of it.

## Done means

- UI1–UI7 fixed, with tests (UI1 with the fixture above) and screenshots at 1280 and 1440.
- The new rows in findings.md get a "Fixed in" entry.
- The version is bumped, with the IDs in the release notes.

The prompt 4 items in 0.14.0 (archives exported at every collection with coverage notes, L13/L14/AR3 role changes, the SFTP outage) haven't been re-tested live yet; that happens after this release, together with a fresh Windows 11 install.
