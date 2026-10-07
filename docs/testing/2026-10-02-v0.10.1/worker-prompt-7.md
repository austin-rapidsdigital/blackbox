You're working on Blackbox (github.com/casea1/blackbox). 0.17.0 was re-tested live on 7 Oct 2026 on three machines:
- the Windows 11 collector;
- the Server 2025, switched to standalone through the setup window on its console, with the status icon then tested after a fresh logon;
- the Ubuntu 26.04 sender.

Details are in `docs/testing/2026-10-02-v0.10.1/findings.md`, section "0.17.0 re-test".

**Confirmed live, don't regress:** TRAY1 (the first click opens the period window), SETUP1 (both the window and the console), SETUP2, AR2b, UI4b, `blackbox gaps` / `gaps accept`, UI13, UI14, UI15, and SCAP results from a sender.

Same owner decisions and working rules as before.

## 1. LOCK1 (High): a run that dies blocks collection for 2 hours, silently

The Ubuntu installer was killed during its first run (SIGPIPE; a crash, `kill -9`, power loss or an out-of-memory kill do the same). `/var/lib/blackbox/blackbox.lock` (PID 31025) stayed behind. For the next 30 minutes, until it was removed by hand:
- every scheduled run logged "waiting for the run in progress to finish" and then "run failed: another Blackbox run is in progress (lock file …)";
- nothing was collected or sent;
- `blackbox status` said "Last collection: 12:45 (31 minutes ago)" and exited 0.

`Store.Lock` (`internal/store/store.go`) only removes a lock older than 2 hours, and never checks whether its owner is alive.

Fix, on Linux and Windows:
1. Prefer an OS lock the kernel releases when the process dies: `flock` on Linux, `LockFileEx` on Windows, on a handle kept open for the run. Keep writing the PID and time into the file for diagnostics.
2. If you keep the file lock, treat it as stale when its PID isn't running. Check the process start time too, so a reused PID isn't trusted.
3. When a scheduled run is refused because of the lock:
   - `status` says "Collection is blocked: a run has held the lock since <time> (PID n)" and exits 4;
   - the tray shows it;
   - it reaches the next report's Audit health as a gap in collection.
4. Tests: a lock left by a killed process (start a child, `kill -9` it, then run), and one held by a live run.

## 2. TRAY2 (minor): the icon's menu takes about 8 seconds to appear

On the Server 2025 VM the menu appeared about 8 seconds after the click. `showMenu` recalculates the full status (`a.Health()`) before showing the menu. An administrator will click again, which may be part of what the owner reported as needing two clicks. Show the menu at once with the last known status, and refresh the status lines in the background (or after the menu closes).

## 3. L13c (minor, docs)

A "Missing 1-280" gap recorded before 0.14 didn't clear after a 0.17 batch from that sender, because nothing in the sender's batches says where its earlier batches went. `gaps accept` covers it. Say in the release notes and in lan.md that gaps from before 0.14 may need `blackbox gaps accept`.

## 4. LOG1 (owner report): "events lost" with 15-minute collection and the log sizes `check` asks for

The owner sees "events overwritten" on several systems, though they collect every 15 minutes and the log sizes match what `check` recommends. Reproduced on the Windows 11 VM:
- every rollover Blackbox recorded since 5 Oct is in **Microsoft-Windows-PowerShell/Operational**;
- the 7 Oct report's "Events lost to log rollover: WIN11-TEST: 447" was 447 events overwritten in **9 minutes**.

The cause:
- That log's Windows default is 15 MB.
- With script block logging (WN11-CC-000326, plus Windows' automatic logging of "suspicious" blocks), each 4104 event is about 34 KB, so the full log holds about 460 events.
- Any admin session or management script (SCCM, Intune, Ansible, WinRM, SSH) can turn it over in minutes, faster than any collection interval.
- The Server 2025 shows the same: 15 MB, full, 556 records.
- `check` sizes only Security, System and Application, so a system set up exactly as `check` says still reports losses.
- The status advice, "collect every 15 minutes … or make the log larger", is misleading here: 15 minutes wouldn't help, and no size is given.

Fix:
1. **Add a `check` line for the PowerShell/Operational log size**, and for any other channel Blackbox reads that can roll over quickly.
   - Recommend a minimum, e.g. 1 GB, or the size that holds a week at the observed rate.
   - Give the way to set it: there is no GPO under Event Log Service for this log, so give `wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:<bytes>` or the registry-based policy.
2. **Name the log wherever a loss is shown** (Overview checklist, Audit health gap, tray, status): "PowerShell log on WIN11-TEST: 447 events overwritten", not "WIN11-TEST: 447 events".
3. **Base the advice on the rate.**
   - If the loss happened faster than the collection interval, say the log is too small for its volume, and give the size needed.
   - Don't suggest 15 minutes to a system that already collects every 15 minutes.
4. **Keep severities apart.** Security-log loss stays High. Show PowerShell/Operational loss as its own, lower-severity line, and say that the per-collection original-log exports kept what was there before each overwrite.
5. **Tests:** a channel with a gap where `collect_every` is already 15m (no "collect every 15 minutes" advice), and the log name in each message.

## Done means

- LOCK1 is fixed with tests on both OSes, TRAY2 is fixed or explained, L13c is documented, and LOG1 is fixed with tests.
- The new rows in findings.md get a "Fixed in" entry.
- The version is bumped, with the IDs in the release notes.

Still to re-test live: a fresh Windows 11 install (A13/A16/A17 noise), the SFTP outage end to end (L12), and the status icon on the owner's own PC.
