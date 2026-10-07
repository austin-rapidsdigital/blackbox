You're working on Blackbox (github.com/casea1/blackbox). 0.19.0 (with 0.18.0 and 0.18.1) was tested in depth on 7 Oct 2026, on three machines:
- the Windows 11 collector;
- the Server 2025 standalone, including its status icon on the console;
- the Ubuntu 26.04 sender.

Details: `docs/testing/2026-10-02-v0.10.1/findings.md`, section "0.19.0 deep test", with screenshots in `v0.19.0/` and every action in test-activity.log.

**Confirmed live, don't regress:**
- LOCK1: legacy lock, `kill -9`, a frozen run → BLOCKED with exit 4, recovery, and "Collection was blocked" on the collector;
- TRAY2 (menu in about 1 s) and Collect now's "Collection finished";
- LOG1 naming, the `check` log sizes, and the severity split in "Events lost";
- the report ledger: missing, changed, accept, Application event 100, the index refreshed at each collection;
- no XSS from event data or `site_name`, CSV formula escaping, and `config set` validation.

Same owner decisions and working rules as before.

## 1. Original logs (do first)

- **AR5 (High): one missing piece stops archiving for good.**
  - `archive.Pack` returns on the first file it can't open (here a piece deleted by hand). The pack fails at every run and scheduled report ("will try again next run"), and the scheduled report ships without `logs-<host>.zip`.
  - `status` only says "waiting in …\archives", and the Original logs page only says "Missing".
  - Fix:
    - pack what is there, and record each missing or unreadable file as a gap in `archive.json`, with its source and time span;
    - remove the piece;
    - while packing fails, `status` says "ORIGINAL LOGS NOT ARCHIVED since <time>: <reason>" and exits 4;
    - the reason is shown on Original logs and in Audit health.
  - Test with a deleted piece and with an unreadable one.
- **AR6: hash the pieces when they are exported.**
  - `piece.json` has `"sha256": ""`. Fill it in at export, and check it when packing. A mismatch is a High row and a note in `archive.json`, and the file is still packed, marked as changed.
  - Add a watch on `/var/lib/blackbox/archive-pieces` (`-p wa`) to `check --audit-rules`.
- **LEDGER1: the ledger must cover the files, not just the manifest.**
  - Moving `logs-<host>.zip` out of a scheduled report, or editing `report.html`, leaves `reports` at OK and `status` at exit 0.
  - At each run, check that every file in the manifest exists with its size. Daily, verify the full hashes (at least the `logs-*.zip`).
  - Report problems as "REPORT CHANGED: <file> missing/changed" through the existing path.
- **LEDGER2:** keep an accepted report in All reports as a muted row: "Accepted as moved by <who> on <date>: <why>".

## 2. Log clears and losses

- **LC1 (High): name the cleared log.**
  - Any `log_cleared` event is summarised as "Security log cleared" (`overview.go:172`, `overview.go:347`, `systemspage.go:404`). Here it was the PowerShell log (System 104).
  - Use the log from the event ("PowerShell log cleared"), and keep "Security log cleared" for 1102.
  - Add tests with a 104 for a non-Security log.
- **LC2: a clear is not rollover.**
  - Clearing the PowerShell log also produced "200 events overwritten" and "Make it at least 16.4 GB".
  - When the oldest record passes the bookmark and that log has a clear event in the interval, don't record a rollover loss and don't give size advice.
- **LOG1b: make the size advice consistent and applicable.**
  - `status` asks for 5.1 GB or 16.4 GB, while `check` asks for 1 GB (fix: 2 GB). Use one rule, capped as in `check`.
  - REG_DWORD can't hold more than 4,294,967,295. The channel key has `MaxSizeUpper` for larger sizes. Cap the advice below 4 GB, or give both values.
  - "holds about 0 hours" → "about 1 minute".
  - The "LOGS INCOMPLETE" lines:
    - apply the critical/other split: the PowerShell log alone must not make `status` exit 4;
    - drop "or collect more often" when that wouldn't help;
    - don't print a zero-length span ("from 06:17 to 06:17").
- **TIME1:**
  - drop 4616s that change the clock by 0 seconds;
  - raise a detection (Medium) when a person moves the clock by more than 5 minutes;
  - keep the time service's own small corrections as they are.

## 3. Audit health and roles

- **STIG1: each system keeps its own STIG IDs.**
  - The gaps table shows "WN25-AU-000070, WN25-AU-000080" for a row shared by the Server 2025 and WIN11-TEST, whose IDs are WN11-AU-000010 and WN11-AU-000005.
  - Split the row per STIG, or list the IDs per OS, in the table and in the CSV.
- **ROLE1:** a former collector, now standalone, still reports its old senders ("2 systems need attention: ubuntu-server: no collection received" under a "1 system" header), while `status` is silent.
  - When the role changes, offer to remove former senders, or leave them out of a standalone's report.
  - On a collector, mark a sender whose last batch says it left.

## 4. Small

- **TRAY3:** the tooltip says "1 thing to look at", but the menu (since 0.18.1) never says what. Drop the count, or add one line pointing to Status details.
- **UI18:**
  - the Audit health tables and header tools overflow at phone width; scroll them inside their panels;
  - a one-day manual report says "Nothing unusual this week": say "this period".
- **CLI1:**
  - non-root on Linux: "run with sudo" instead of "open /etc/blackbox/blackbox.conf: permission denied";
  - use ASCII instead of em dashes in console output, or set the code page, so output redirected in PowerShell 5.1 isn't mojibake;
  - the Windows `install --yes` upgrade should collect, as the Linux one does;
  - `keep_sent_days 0` should say it turns off resends.
- **CONF1:** the `blackbox.conf` template still says "Events are collected every hour regardless, so nothing is lost to log rollover" (`config.go:497`). Reword it.

## 5. UI/UX: simple, no duplicated data (owner request)

The owner wants the report "simple yet detailed", like Splunk, with no duplicated data to confuse auditors. Detections, Inventory and Search are the model. Details: findings.md "UI/UX review, every page", with screenshots in `v0.19.0/ux/`.

**Rule for all of it:**
- each fact is shown once, where it belongs, and everything else links to it;
- repeats become one row with a count;
- a panel with nothing to show is one line, or is hidden.

- **UX1 (do first): fold duplicate rows, and count the folded rows everywhere.**
  - `conhost.exe` children are 500 of 859 privileged rows: fold them into the parent.
  - The split-token 4624 pairs are 33 of 74 logons: join them on `TargetLinkedLogonId` into one logon "with administrator rights".
  - Identical rows (same system, person, action and text within a minute): one row "×N", with every record kept in the detail.
- **UX2:** Audit integrity labels all 33 rows "Logging stopped" (an upgrade, a firewall rule, task updates). Label each kind, and count only real stops in the tile.
- **AR2c (regression):** export-piece writes from a hand-run `blackbox run` on 0.19.0 are High again (17 rows; 7 of 8 People "Notable actions"; 2 false "Possible covering of tracks" in the scheduled report). Find why `exportWrites` misses them, and add a fixture from these records.
- **UX3: one fact, one place.**
  - Overview: one "Needs attention" list, each problem once; 4 headline tiles; non-zero activity counters only, with the zeros in one line; no system tiles.
  - Systems page: the reporting problem once; the audit gaps as a count linking to Audit health.
- **UX4: empty states.**
  - A page with no events is one line.
  - "Not enough history" is said once, and trend tiles are hidden until there is history.
  - Fix the "1, 0, 0" y-axis.
  - Use hours for a period of a day or less, and never mark "Above normal" without a baseline.
- **UX5:** give every number its scope ("this report" / "this week, all reports"), and reconcile Privileged actions 4,074 (trend tile) with 1,901 (Trends grid, same week, one person). Also reconcile Systems reporting 3 vs 4, and "High-severity events 113" next to "Detections 0".
- **UX6:** two words, Detections (investigate) and Health (fix). A High row that is not in a detection is Medium, or a detection. Drop "Flagged this week" / "Notable" / "something unusual".
- **UX7:**
  - hide a column whose values are all empty or all the same (Severity "—", Session, Kind);
  - drop the person's name from table summaries ("claude ran with …") and keep it in the detail.
- **UX8:** SSH logons show "From: local". Join OpenSSH/Operational's "Accepted … from <address>" to the 4624, so the source address is shown.
- **UX9:**
  - Sidebar: Overview, Detections, Search, Systems, People, Audit health, Original logs, All reports, with the event categories as chips in Search (zero-count hidden).
  - The manual-report banner becomes a chip after the Overview.
  - "this week" → "this period".
  - Time labels on the Search timeline.

Check the result against the same report data: Privileged activity should drop from 859 to about 360 rows and Logons from 74 to 37, with the same information.

## Done means

- AR5, LC1, LC2, LEDGER1, AR2c, UX1 and UX2 are fixed with tests on both OSes, and the rest are fixed or answered.
- The new rows in findings.md get a "Fixed in" entry.
- The version is bumped, with the IDs in the release notes.

Still to re-test live:
- a fresh Windows 11 install (A13/A16/A17);
- the SFTP outage end to end (L12);
- the status icon on the owner's PC;
- a ledger record removed under retention_days.
