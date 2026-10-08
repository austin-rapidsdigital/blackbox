You're working on Blackbox (github.com/casea1/blackbox). 0.20.0 was re-tested live on 7 Oct 2026 on three machines, all upgraded in place:
- the Windows 11 collector;
- the Server 2025, standalone;
- the Ubuntu 26.04 sender.

Details are in `docs/testing/2026-10-02-v0.10.1/findings.md`, section "0.20.0 re-test", with screenshots in `v0.20.0/`.

**Confirmed live, don't regress:**
- AR5, AR6;
- LEDGER1 (0.20 reports);
- LC1, TIME1;
- LOG1b on Windows 11, and PowerShell loss no longer making `status` exit 4;
- AR2c;
- STIG1, ROLE1, UI18;
- the Linux exports rule;
- install collects;
- the simpler Overview, sidebar and Search chips.

Same owner decisions and working rules as before. Items are labelled **must fix** (wrong data, lost original logs, false or doubled alerts, misleading an auditor) or **backlog**.

## 1. AR7 (must fix, High): original logs silently left out of every scheduled report

The packed archive names each `.evtx` by its piece's start, to the minute (`stampFormat = "20060102-1504Z"`). Two pieces started in the same minute on Win11 (runs at 13:17 and 13:17), so the daily archive held `Security_20261007-1317Z.evtx` **twice**.

What happened at the scheduled report:
1. `archive.Bundle` → `Verify` failed: "does not match its recorded SHA-256 (damaged or altered); they stay pending".
2. The report was written with no `logs-*.zip`.
3. `status` exited 0.
4. A manual report said "Also fine: Original logs archived", and Original logs said the next scheduled report holds them.

`bundleLogs` makes one zip per computer from all its pending archives, so every later scheduled report fails the same way, and that computer's original logs never reach a report. Two runs in one minute are ordinary: Collect now, a hand run, setup, or a run that waited for the lock.

Fix:
1. **Unique names:** seconds plus the piece number, or a folder per piece. `Write` refuses a duplicate name.
2. **One bad archive must not hold back the rest:**
   - bundle the archives that verify;
   - keep the bad one aside, named, for the administrator;
   - record it as a gap in that report.
3. **Say so:**
   - `status`: "ORIGINAL LOGS NOT IN REPORT <name>: <reason>", exit 4;
   - the report's Overview, Original logs and Audit health give the reason;
   - "Also fine: Original logs archived" only when they were.
4. **Recover what is already written:** an archive with duplicate entry names can still be read in order. Re-pack it, or bundle it with its entries renamed, when its manifest lists both hashes.
5. **Tests:**
   - two pieces in the same minute;
   - one bad archive among good ones;
   - a collector bundling a sender's bad archive.

## 1b. The original logs must not depend on time (must fix, High)

An assessor-style check of a real scheduled report traced every row to its original record. Windows Security was complete, but two holes were found (findings.md "Assessor test").

- **AR8: Linux audit records written in the same second as a run are lost.**
  - The 6 Oct report's `audit.log` is missing 33 serials in 6 places, each in the first second of a Blackbox run. 16 are rows in the report itself, with no original record.
  - On 0.20.0, the sender's pieces miss 26 serials in 11 places: e.g. 41323 is between piece 000096 (ends 41322) and 000097 (starts 41324), yet it is in `/var/log/audit/audit.log`.
  - Cause: pieces are cut at the run's exact time (`[from, to)`), but `auditTime` in `export_unix.go` drops the milliseconds. A record written in that second, after the cut, reads as earlier than the next piece's `from`.
- **AR9: anything logged while the clock is set back is never exported.**
  - Exports select records stamped after the previous export's end.
  - Win11's clock was moved back 10 minutes for 20 seconds. Security 172279-172285 are missing from the pieces: the 4616 clock change itself, and a logon (4624/4672) made while the clock was back. No gap was recorded.
  - The System log lost 1605-1627 the same way after a VM clock jump.
  - Moving the clock back is how someone hides activity.

Fix:
1. **Export by position, not time.**
   - Windows: `EventRecordID` greater than the last one exported, per channel. `wevtutil epl` takes it as an XPath query. Keep the last ID in the state.
   - Linux: the audit serial, or the file offset and inode, as collection already does.
   - Time stays in `piece.json` for display only.
2. **Check continuity.** Each piece starts at the record after the last one. A jump is a recorded gap ("records N-M were not exported: …"), which `status` and the report show.
3. **Tests:**
   - an audit record in the same second as the cut;
   - the clock set back, a logon, the clock set forward, then a run: the 4616 and the logon are in the next piece;
   - rotation of `audit.log` between runs.

**AR10 (backlog):** a sender's `logs-*.zip` covers its own day (6 Oct 00:00Z to 7 Oct 00:01Z), not the report's period (6 Oct 07:00Z to 7 Oct 07:00Z). `docs/reports.md` says "covering the report's period". Cut senders' archives at the collector's report boundary, or show each computer's coverage on Original logs, with where the rest is.

**ASSESS1 (backlog):**
- a `README.txt` in each report folder: the files, how to check them (`sha256sum -c manifest.sha256` / `Get-FileHash`), how to open the logs (`Get-WinEvent -Path (Get-ChildItem *.evtx)`, `ausearch -if audit.log`), and the time zone;
- a time zone on `events.csv` times;
- `wevtutil al` so message text shows on other computers.

## 2. Logs and the ledger

- **LC2b (must fix):** after `wevtutil cl` on the PowerShell log, `status` added "Logs incomplete: … had already overwritten its events from 16:24 to 16:25 … Make the log larger". Label a gap that follows a clear (System 104 / 1102) as "cleared by <who> at <time>", with no size advice.
- **LEDGER1b (must fix):**
  - Reports recorded by 0.19.0 have no file list, so a logs zip moved out of one went unnoticed (status exit 0) until the daily hash, up to 24 hours later. On upgrade, fill in each record's file list from its manifest.
  - `blackbox reports` should exit 4 when it lists CHANGED or MISSING, like `status`.
- **LEDGER3 (must fix, wording):** moving one zip out of a report folder showed as High "claude deleted the report 2026-10-06_0000_4-systems". Name the file and keep the report name: "deleted logs-WIN11-TEST.zip from the report …".
- **LOG1c (backlog):** `status` prints one "Logs incomplete" line per gap (6 on Win11), each ending "or collect more often (collect_every 15m)", while the "Events lost" line says collecting more often would not help. Show one line per log, with the count and the latest range, and the same advice.
- **LOG1d (backlog):** on the Server, `check` says "make it 1 GB" for the PowerShell log, and `status` says "at least 2 GB". Use the same rate-based size in both.

## 3. Duplicates still in the report

- **UX1b (must fix, from prompt 8):**
  - Each SSH logon is still two rows at the same second: "claude logged on via SSH (OpenSSH) from 192.168.1.11 with administrator rights", and the same with no address. That's 24 logons as 48 rows. Join the split-token 4624 pair on `TargetLinkedLogonId` into one row.
  - 16 rows "ran with administrator rights: conhost.exe 0xffffffff -ForceV1" remain. In SSH sessions conhost's parent is sshd, which isn't a row, so the fold doesn't apply. Drop or fold a conhost whose parent isn't shown.
  - Check: the Logon activity count equals the number of logons.
- **DUP2 (must fix):** one `wevtutil cl` gave two High detections, "Command that can clear logs or weaken auditing" and "Log cleared". Fold the command into the clear's detection when they match (same system, person and log, within a minute), and keep the command line in its details.

## 4. Backlog

- **UX10:**
  - the unlabelled "2/3", "1/3", "0/3" in the Overview Health list (say "2 of 3 systems");
  - "Also fine: Logs intact" shown next to "Logs cleared";
  - Audit health's "Events lost to rollover 0 · 2 runs" (say what the runs are);
  - `config show` "report_at Wednesday 00:00 (daily at 00:00)" (hide the weekday when daily);
  - Ubuntu Server listed under WORKSTATIONS;
  - at phone width, the host and time of a detection card are cut off.
- **CONF1b:** an upgrade keeps the old `blackbox.conf` comments ("Events are collected every hour regardless"). Refresh the comments on upgrade, keeping the values.
- **T2b (idea):** a 5038 for a file under `Windows Defender\Platform\` stays High with "how to check". Blackbox reads Defender/Operational, so it can do the check itself: a platform update (2000/2014) within minutes makes it Medium "during a Defender update".

## Done means

- AR7, AR8, AR9, LC2b, LEDGER1b, LEDGER3, UX1b and DUP2 are fixed, with tests.
- The new rows in findings.md get a "Fixed in" entry.
- The version is bumped, with the IDs in the release notes.

Still to re-test live:
- a fresh Windows 11 install (A13/A16/A17);
- the SFTP outage end to end (L12);
- the status icon on the owner's PC;
- a ledger record removed under `retention_days`;
- a week of normal operation through a weekly report.
