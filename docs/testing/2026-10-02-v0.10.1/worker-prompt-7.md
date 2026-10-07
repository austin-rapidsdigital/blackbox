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

## Done means

- LOCK1 is fixed with tests on both OSes, TRAY2 is fixed or explained, and L13c is documented.
- The new rows in findings.md get a "Fixed in" entry.
- The version is bumped, with the IDs in the release notes.

Still to re-test live: a fresh Windows 11 install (A13/A16/A17 noise), the SFTP outage end to end (L12), and the status icon on the owner's own PC.
