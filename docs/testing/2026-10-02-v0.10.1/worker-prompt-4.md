You're working on Blackbox (github.com/casea1/blackbox). Your third work list and its addendum shipped as 0.12.0/0.12.1 (#43–#48). They were re-tested live on 5 Oct 2026 on three machines:
- a Windows 11 Pro 25H2 collector, previously standalone;
- an Ubuntu 26.04 machine, first a sender over SFTP, then SMB, then standalone;
- a Windows Server 2025, first a collector, then a Windows sender.

This round also tested SMB between machines, a dead SMB mount, role changes and the original-log archives for the first time. Results are in `docs/testing/2026-10-02-v0.10.1/findings.md`: the sections "v0.12.1 verification", "Original-log archives", and the rows L13, L14, S14, S15 and N2b. The actions are in test-activity.log.

Same lens and owner decisions as before (`docs/design.md` §13): report only, no third-party dependencies, plain-English sentences, no sign-off section.

**Confirmed live, don't regress:**
- *Clock:* T1, T3 (detection, `status` exit 4, collection-order reports).
- *Linux:* U4b, U5, U6, U8b, A14b, A15, O1 (live journal), U13, U14, U15.
- *Windows:* W1 (local), R10, A5/A15 on Windows, S13.
- *SCAP:* SC1, SC3.
- *Delivery:*
  - L6, L8, L10 text, L11 resend (duplicate ignored).
  - L12: proved by hand, and covered by your CI.
  - SMB between machines: SMB 3.1.1 with `seal`. A dead mount doesn't stop collection and recovers by itself (the `soft` mount).
  - Mixed sender/collector versions; the Windows sender over SMB.
- *Archives:* `.evtx` and Linux archives open; `verify` catches a changed `.evtx` inside `logs-*.zip`.

Same working rules: one PR per group, tests (real-record fixtures where given), gofmt, vet on Linux and Windows, docs in the same PR, IDs in commit messages.

## 1. Original-log archives (do first; AR1 and AR2 are High)

The owner wants the original logs (`.evtx` on Windows, the raw audit and syslog files on Linux) kept complete and secure as evidence. Today the archive is a once-a-day `wevtutil epl` / line copy for the time since the last archive, chained by time (`ArchivedUntil`).

- **AR2 (High): a daily export misses what the log already overwrote, and the archive doesn't say so.**
  - On the STIG-audited Windows 11, one Windows Update run made the default 20 MB Security log roll over within an hour (C6: 94,565 events lost).
  - The first archive claims 28 Sep → 5 Oct, but its `Security.evtx` starts at 5 Oct 04:08, and `archive.json` has no note. An assessor will take it as complete.
  - Fix:
    1. Export at every collection, so originals are taken while the log still has them. `wevtutil epl` with the time query is cheap; append the pieces to the pending daily archive (several `.evtx` per channel is fine, or merge them). Do the same on Linux for the `audit.log` lines, where rotation (5 × 8 MB by default) can also outrun a day.
    2. In `archive.json`, and in the report's Original logs page, record for each log: the period actually covered (the oldest record present), and the events Blackbox knows were overwritten before export. For example: "Security: covers from 04:08; 94,565 events were overwritten before they could be exported".
    3. A test with a log that has rolled over.
- **AR1 (High): after the clock moved back, a stretch of original logs is never archived.**
  - `ArchivedUntil` was set to 07:00Z while the clock was 3 hours fast. After the correction, everything stamped 03:02Z–07:00Z falls between two archives, including the original records of a log clear and a settings edit.
  - T3 fixed this for reports, not archives. When T3's "clock moved back" is detected, restart the archive chain from the last real export, cover the skipped stretch, and note it in `archive.json` and the report.
  - Test: move the clock forward, export, move it back, export.
- **AR3: archives are stranded when a collector becomes a sender.**
  - The Server 2025 still holds, pending, Ubuntu's archives for 25 Sep → 4 Oct and its own for 4–5 Oct in `archives\`. As a sender it will never bundle them, and it doesn't forward them.
  - On a collector → sender (or → standalone) switch, either forward pending archives (yours and other systems') to the new collector, or produce a final report that bundles them. Say in setup which happened.
- **AR4 (proposal, write it up in design.md §13 for the owner first): an off-box copy.**
  - On a standalone PC or a collector, archives sit only inside the report folders on the same disk. An administrator can delete them; the SACL/audit rules record it, but the evidence is gone. This matters for AU-9(2) and AU-4(1).
  - Propose an optional `archive_copy_to`: a removable drive, a write-once share, or a second server. Each report's `logs-*.zip`, `manifest.sha256` and `summary.json` are copied there; a failed copy is a warning in `status` (exit 4) and in the next report.
  - Also document that archives are deleted with their report under `retention_days`.

## 2. Role changes and gaps between collectors

- **L13: changing a sender's collector raises a false "data lost" alarm.**
  - Ubuntu moved from the Server 2025 collector to the Windows 11 one. The new collector says "Missing: batches 1-280 from ubuntu-server never arrived", and since 0.12 adds "To send them again, run on ubuntu-server: blackbox send --resend 1-280". Those batches went to the previous collector, and the sender may not keep them.
  - When `send_to` changes, the sender marks its next batch as the first for this destination ("starts at batch 281; earlier batches went to WIN-498EC8UMUEL"). The new collector starts gap-counting there.
  - Only suggest `--resend` for batches the sender says it still keeps.
- **L14: a collector that becomes a sender forwards everything it received, and the new collector mislabels it.**
  - Server 2025's first batches as a sender carried 9,058 records, including Ubuntu events it had received as a collector.
  - Windows 11 then lists ubuntu-server as "via WIN-498EC8UMUEL", although Ubuntu delivers to it directly, and still shows batches 1-280 missing although their events just arrived.
  - Choose and document one behaviour:
    - (a) forward received data once, marked relayed, and have the new collector match it against the original sender's batch numbers, so the gap clears; or
    - (b) don't forward other systems' data, and tie that to AR3's final report.
  - Keep "via" only for systems that are seen only through a relay. Test for duplicates when both paths deliver.
- **W1b:** relayed data carries the former collector's **former** name (`WIN-R5L5B9EF403`, 42 events). The new collector shows it as a 4th system and names the report "4-systems". `formerNames` only folds when one computer of that OS collects there. Send each system's known former names with its batches, and fold by them.
- **S14 (minor):** a setup run while a scheduled run held the lock said "Done, but the collector could not be reached yet: another Blackbox run is in progress". Say "a collection was already running; this computer's events go at the next run".
- **S15 (minor):** sender → standalone on Linux removes `blackbox-shutdown.service`, but systemd keeps it as "not-found failed" (`systemctl --failed`). Stop it and `reset-failed` it when removing it.

## 3. Smaller items from the 0.12.1 re-test

- **T3b:** an interim report leaves out events stamped up to `clockSlack` after its creation time ("belongs to a later report"). After a clock correction, the Security log clear (1102), 4719 ×2 and 4616 ×2 were collected at 06:44:14 but stamped 06:45:06, and the interim at 06:44:44 didn't show them. For interim reports, include everything collected so far, whatever its stamp.
- **T1b:** after the clock moved back, the Systems table still shows the computer's last collection as "2026-10-06 00:02" (the future), while the `status` header shows 06:44. Show the latest collection by collection order, and mark a future time.
- **A17b:** High "Possible covering of tracks: claude created the user account bbsend2 … less than a minute later: … changed Blackbox's inbox setting". This is setting up a collector: creating the delivery account, then running Blackbox setup. Don't pair account creation with Blackbox's own self-recorded setup changes.
- **U4c:** commands started by the login scripts still leave rows on Ubuntu 26.04: Low "AppArmor blocked who from open on /etc/nsswitch.conf" and "…/etc/passwd" (`who`, from 50-landscape-sysinfo), and "changed the permissions of /var/lib/landscape/landscape-sysinfo.cache (using chmod)". Fold AppArmor denials and file changes made by processes inside the login-script chain into the same Info row.
- **L11b:**
  - `blackbox send --resend 1-3` exits 0 when none of them is kept ("Not kept on this computer: 1, 2, 3"); exit non-zero when nothing was resent.
  - The collector logs a resent duplicate as "received 1 batch (0 records)"; say "1 batch already imported".
- **N2b (check):** Windows 11 25H2 enables "File and Printer Sharing (Restrictive) (SMB-In)" (Public, Allow) when a share is created, while the classic SMB-In rules stay disabled. SMB worked, and Blackbox rightly didn't warn. Make sure the N2 check counts the Restrictive rule as open (add a test), and that it still warns on Server 2025, which may not have that rule.
- **C6 note:** existing installs keep `collect_every = 1h` on upgrade (the new 15-minute default only applies to new installs). While events are being lost to rollover, have `status` and the report suggest `blackbox config set collect_every 15m` explicitly.

## 4. Release (owner action, not yours)

A10: still unsigned. The owner will add the secrets. Once the release key exists, put its public key and fingerprint in the README's "Verifying a release" section.

## Done means

- Everything above is fixed with tests. AR1/AR2 need a rolled-over log and a moved-back clock in their tests.
- AR4 is written up for the owner.
- The new rows in findings.md get a "Fixed in" entry.
- The version is bumped, with the IDs in the release notes.

Not testable by you, re-tested live afterwards: a fresh Windows 11 install (A13/A16/A17 noise), the SFTP outage end to end (L12), and the role-change flows (L13, L14, AR3).
