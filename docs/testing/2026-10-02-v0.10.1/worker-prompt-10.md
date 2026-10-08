You're working on Blackbox (github.com/casea1/blackbox). 0.21.0 was tested end to end on 8 Oct 2026. The details are in `docs/testing/2026-10-02-v0.10.1/findings.md`, section "0.21.0 full test", with screenshots in `v0.21.0/`.

**What was tested:**
- three machines, upgraded in place: the Windows 11 collector, the Ubuntu 26.04 sender and the Server 2025 standalone;
- a manual report and a scheduled report;
- a set of auditable actions on both OSes;
- an accessibility pass;
- a source review with Go tests;
- a compliance review of the STIG IDs and NIST claims.

`v0.21.0/review-tests/` holds Go tests that **fail on v0.21.0**. Copy each one into the package it names (`internal/lan`, `internal/report`, `internal/app`), make it pass, and keep it. Two existing tests (`TestStandaloneShowsOnlyItself`, `TestNoBatchSince`) fail on any machine named `claude-code`, because they use that as a sender's name; give them a name no build machine has.

**Confirmed live, don't regress:**
- AR7 (repair to `…-2.evtx`, and a note in `archive.json`);
- LEDGER3 / LEDGER1b;
- LOG1c, CONF1b, UX1b, DUP2;
- the upgrade config refresh;
- Windows coverage of account, group, policy, firewall, service and task changes;
- no HTML/JS injection in reports;
- CSV formula guarding;
- keyboard focus.

The prompt-9 items still open are AR8, AR9 (original-log records lost by time-based export), AR10 and ASSESS1. They stay as written there. Same owner decisions and working rules as before. Items are labelled **must fix** (wrong or lost data, evidence that can be hidden, misleading an auditor) or **backlog**.

## 1. The inbox is a trust boundary (must fix, High): SEC1, SEC2

Today any account in `Blackbox Senders` has Modify on every file in the inbox. Batches and archives carry only checksums. On the rig, the Ubuntu sender's account read and deleted a file left for another host, and nothing recorded it.

1. **Per-sender folders.**
   - Give each sender its own folder in the inbox, with write access for that sender's account only (create files, no delete or overwrite of existing ones).
   - Map each folder to the host names and sender IDs it may deliver. The collector rejects a batch, archive or SCAP file whose sender ID or host is not that folder's.
   - Record who wrote each file (the file owner, or the share account from the SMB session) in the import record.
   - Keep the old shared folder working for one release, with a `status` warning.
   - Linux SFTP: the same layout, one directory per account.
2. **Sequence numbers can't be moved by a batch.**
   - Ignore `first_seq` unless it is at most the next expected number plus a small window, and record a jump as a gap. Never erase recorded gaps because of `first_seq` (`receive.go:269-285`).
   - Count a batch as "already imported" only if its content hash matches the one imported under that number. If it doesn't, keep both and raise a High row: "two different batches 214 from DC01".
3. **Archives and SCAP results.**
   - Their host must match the folder's host.
   - When an archive for the same period already exists, compare hashes. If they differ, keep both and raise a High row; never delete the newcomer unread (`archive.go:441-447`).
   - SCAP: check the hash in the file name, and reject a host that isn't the folder's.
4. **Former names.**
   - Accept `former` only for names this sender ID used before, or names an administrator accepts (`blackbox systems rename OLD NEW`).
   - A claimed former name that belongs to another live sender is a High row, not a merge.
5. **Cloned senders.** When two different hosts send under one sender ID, keep both batches. Say "two computers are using one sender ID (a cloned machine?): run `blackbox send --new-id` on one", and add that command.
6. **The sender's "already delivered".** An existing file in the inbox under the next name counts as delivered only if its hash matches; otherwise write under a new name (`lan/send.go:388`).
7. **SEC2: a bad batch must not block the queue.**
   - Move a batch that fails to import to `inbox\rejected\` with a `.why.txt`, raise it in `status` (exit 4) and in the next report, and go on with the rest.
   - Keep the sender's number as a gap until it is resent.
   - Add tests for a bad event line, a bad time, and an unknown record type.
8. **Smaller:**
   - SEC3a: reject host names `.`, `..` and names with path separators after `SafeName`.
   - SEC3b: stat the file and refuse a `.bbx` larger than the limit before reading it.
9. **Tests:** the five review tests in `review_lan_test.go` and `review_app_test.go`, plus a test that one sender can't write into another's folder (Windows ACL test, or a fake FS).

## 2. Ubuntu 26.04 SSH logons are missing (must fix, High): LNX1

With auditd present, logons come only from `USER_LOGIN`, and Ubuntu 26.04's `sshd-session` writes none. On the rig, 48 SSH sign-ins since 7 Oct gave 0 Logon activity rows.

The logon is still recorded in two places:
- `USER_START … op=PAM:session_open … exe="/usr/lib/openssh/sshd-session" hostname=… addr=… terminal=ssh res=success`;
- the auth.log line `sshd-session[pid]: Accepted publickey for claude from 192.168.1.11 port … ssh2: ED25519 SHA256:…`.

What to do:
- When no `USER_LOGIN` came for a session (match by `ses`/pid within a few seconds), make the logon from `USER_START` with `terminal=ssh`. Take the method and key fingerprint from the auth.log line when it is there.
- For failures, use `USER_AUTH res=failed` and auth.log's `Failed …`/`Invalid user` lines.
- `check`: warn when sshd is installed and the audit log holds `USER_START` from sshd but no `USER_LOGIN`.
- Add fixtures taken from this machine (tester can supply them).
- Document Ubuntu 26.04 as supported, or not.

## 3. Folding must not merge separate actions (must fix): DUP3, DUP4

- **(a) Log clears.** A clear is one action per `wevtutil` process / System 104 (or Security 1102) record. Two clears are two rows and two counts, even a minute apart.
  - Fix the detection text: "3 logs cleared … between 16:24 and 18:59", with the right last time.
- **(b) SSH pairs.** Pair two SSH logons only if their source addresses match, or one has none (`merge.go:945-975`). A dropped logon's address must not vanish.
- **(c) The console host.** Fold only `C:\Windows\System32\conhost.exe` (full path, case-insensitive) with the known arguments, started by sshd. Any other path, or a missing command line, stays a row (`merge.go:1009-1081`).
- **DUP4.** Fold the 4688 for `auditpol /set|/clear|/remove` into the 4719/4912 it caused (same account, within a few seconds), as for `wevtutil cl`. One change gives one High row, with "Changed with" showing the command.
- **Tests:** `review_ssh_test.go`, `review_fold_test.go`, two clears a minute apart, and auditpol plus 4719.

## 4. Retention must not delete unreported logs (must fix, High): RET1

- Age report folders by their period end (from `summary.json` / the ledger), not `ModTime` (`app.go:1536-1560`).
- Never prune an archive in `archive_dir` that is not in a report yet (`archive.Prune`). If one is older than `retention_days`, show it in `status` (exit 4) and in the report: "original logs from … have waited N days and were never put in a report".
- The `config set retention_days` prompt, and the docs, should say that the period comes from the site's records schedule (NARA GRS / DoD schedule, ISSM), not from AU-11, and mention legal holds.
- **Tests:** a restored folder with an old modified date is kept, and a pending archive past retention is kept and raised.

## 5. Compliance claims (must fix): COMP1, COMP2, COMP3, DOC1, AU3

- **COMP1 (verify first).**
  - Check WN11-AU-000581/582/584 against the current DISA Windows 11 STIG download. stigaview lists them up to V2R7 but not in V2R8 or V2R11.
  - If they are gone, remove them from `Windows11` in `check/stig.go`, or mark them "Blackbox's advice". Fix `windows.md:234,293`.
  - Update the version line (V2R11, 5 Oct 2026, per the mirror).
- **COMP2.**
  - Cite UBTU-24 (and RHEL 9 / Alma) STIG IDs on the Linux checks where they exist.
  - Word every check without an ID as "Blackbox recommends Y", never "the STIG requires" (`healthpage.go:428-431`).
  - Leave those checks out of "Systems matching STIG" (`healthpage.go:363,644`), and show them as their own count.
- **COMP3.**
  - Build releases with `GOFIPS140=v1.0.0`, and document `GODEBUG=fips140=on` and how to check it (`blackbox version` could print the FIPS module state).
  - If not, remove the claim from `design.md:371`.
- **AU3.**
  - Fill `Outcome` for every event: Windows Audit Success/Failure keywords, and auditd `success=`/`res=`.
  - Where a source gives none, the CSV says "not recorded".
- **DOC1.** Fix these lines in README, security.md, design.md, configuration.md and reports.md:
  - "can't overwrite events" → "collects often, and detects and reports any loss";
  - "never writes to logs" → "never alters or clears log records; writes its own change records (Application event 100, journal `blackbox`)";
  - the SHA-256 manifest detects accidental damage. It supports AU-9b detection, not AU-9a/AU-9(3), until reports are signed;
  - "a year is the usual retention (AU-11)" → the records schedule;
  - remove the apply-baseline and auditpol-backup text (`design.md:189-195,354-356`);
  - AU-5 only within the report/`status` interval, with `status` wired into monitoring;
  - label the AU-8 checks as basic (UBTU-24-600160/600180 not checked);
  - make the control tags in design.md and event.go the same.

## 6. Original logs and integrity (must fix): LC2c, VER2, DST1

- **LC2c.**
  - Record a `cleared` gap whenever a clear is seen since the last export, whatever the file size. `GapsIn` only notes one when the log looks full (`Wraps`), and Windows truncates a cleared file.
  - Remove the contradictory "were overwritten before they could be collected" log line for a cleared log.
  - **Test:** write, clear, and collect on a log at 1% of its size, which gives `status` "Log cleared:" and `archive.json` `cleared`.
- **VER2.**
  - `verify` walks the whole report folder and fails on any file not in the manifest.
  - The ledger also records the file count and notices added files.
  - A listed file it cannot read is a problem, not "verified".
  - **Test:** `review_report_test.go` (TestReviewVerifyIgnoresExtraFolders).
- **DST1.**
  - Give each row its own offset, or split a day's data at the zone change (`report/data.go:150`).
  - **Test:** `TestReviewDSTDayOffset`, plus America/Los_Angeles on 1 Nov 2026.

## 7. Backlog

- **ROLE1b.** A system removed with `systems remove` shows its events in the period as "retired 7 Oct by …".
  - It doesn't count in "Systems reporting", Health problems or "Original logs missing".
  - Its card doesn't say "Events 4" next to "Collected nothing".
- **UX10b.** Record a settings check (with inventory) at install and upgrade, so grouping and fixed settings show at once.
- **STAT2.** Give the PowerShell size advice once in `status`, and round the size to a stable step (1 GB, 2 GB, 4 GB).
- **TZ1.**
  - `archive.json` times are all UTC (`Z`).
  - `status` shows local times only, with the zone once at the top.
- **UI19.**
  - Label Search's and Logon activity's filter selects.
  - Give SVGs `role="img"` with names, or hide them.
  - Fix `aria-conditional-attr` on Inventory, the duplicate landmarks and the heading order.
  - Show Audit health's column names without hover (a key under the table).
  - At 768 px, no horizontal scroll on Audit health.
- **UI20.** At 390 px the Overview tiles wrap their second line instead of cutting it, and the manual banner's label sits above its text.
- **UI21.**
  - "2 logs cleared".
  - Bundling-time detections ("Saved original log changed …") say they came from Blackbox's own check at bundling, with no empty "What happened"/"Involved" boxes, and are timed in the period or labelled "found when this report was made".
  - A 4648 with no process name leaves out "to run .".
  - `powershell -File <path>` is "ran the script <path>", not "typed or run from memory".
- **LEDGER4.** Write REPORT MISSING/CHANGED to the Application log (event 101) and the journal, once per report, so a SIEM sees it.
- **SEC3c.** Keep `blackbox.conf.old` from the first refresh. Name later ones `.old.<version>`, or don't overwrite.
- **SEC3d.** Document the share-credential protection (DPAPI machine scope, readable by Administrators/SYSTEM). Consider user-scope DPAPI for the SYSTEM account.

## Done means

- Every must-fix item above is fixed with tests, and the review tests pass.
- COMP1 has a note saying which DISA release was checked.
- Each new row in findings.md gets a "Fixed in" entry.
- The version is bumped, with the IDs in the release notes.

Still to re-test live after this release:
- the inbox layout on the rig, with the Ubuntu sender and a second sender;
- Ubuntu SSH logons;
- two clears a minute apart;
- a `retention_days` run with a pending archive;
- DST on 1 Nov;
- the prompt-9 items (AR8, AR9);
- a fresh Windows 11 install (A13/A16/A17), the SFTP outage (L12), and a week of normal running.
