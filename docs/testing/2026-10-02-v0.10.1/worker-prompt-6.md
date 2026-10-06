You're working on Blackbox (github.com/casea1/blackbox). 0.16.1 was re-tested live on 6 Oct 2026 on a Windows 11 collector, a Server 2025 sender and an Ubuntu 26.04 machine (switched from standalone back to sender). Reports were viewed in Chromium at 1440 px. Details are in `docs/testing/2026-10-02-v0.10.1/findings.md`, section "0.16.1 re-test", and test-activity.log.

**Confirmed live, don't regress:**
- *Original logs:* AR2 (per-collection exports in `archive-pieces`).
- *Reports:*
  - UI1/UI8 ("Not enough history yet", "This week: 1.4 of 7 days so far");
  - UI2 (a silent sender is red with "no data since …");
  - UI3/UI10/UI11 (Audit health layout and section bar);
  - UI5, UI6, UI7, UI9, UI12;
  - UI4 for the installer's file writes.
- *Delivery:* standalone → sender delivered the standalone period's events.

Same owner decisions and working rules as before (`docs/design.md` §13; one PR per group, tests, gofmt, vet on Linux and Windows, docs, IDs in commits).

## 1. False High detections (do first)

- **AR2b: the per-collection exports raise High rows and a false "covering of tracks" when Blackbox is run by hand.**
  - `wevtutil epl` writes the `.evtx` pieces through the Event Log service. With the folder SACL that `check` recommends, each piece is a 4663 by **svchost.exe**, attributed to the person running Blackbox.
  - A hand-run `blackbox report` gave 12 High "claude changed or deleted Blackbox's data: C:\ProgramData\Blackbox\archive-pieces\000001\Security.evtx (using svchost.exe)". It also gave 2 High "Possible covering of tracks", pairing them with creating the delivery accounts the day before. They were the report's only detections.
  - Scheduled runs as SYSTEM don't show it.
  - Treat writes to `archive-pieces` and `archives` by the Event Log service during a Blackbox run (match the run's time window and the piece names Blackbox wrote) as Blackbox's own. A change or delete there by anything else stays High.
  - Add a test with recorded 4663s.
- **UI4b:** the upgrade's helper commands are 25 Low rows ("claude ran with administrator rights: reg.exe add HKLM\…\Uninstall\Blackbox …", "net share BlackboxInbox", "icacls …", "schtasks /Query …"). Fold processes started by `Blackbox-Setup-*.exe` into its install/upgrade row, as for Blackbox's own child processes (T4).

## 2. The tray (owner report)

- **TRAY1: "Make a manual report…" needs two clicks before the period window appears.** Every time, per the owner; not reproduced here.
  - The dialog is shown with `ShowWindow(SW_SHOWNORMAL)` and then `SetForegroundWindow` (`internal/gui/window_windows.go`, `tray_windows.go` `interimDialog`).
  - A likely cause: a process's first `ShowWindow` call can take the show mode the process was started with (`STARTUPINFO.wShowWindow`), so the first window the icon opens may be created hidden. If so, "Status details…" also fails on its first use after a logon.
  - Reproduce it on Windows 11 with the icon started by the "Blackbox Status" task at logon. Fix it, e.g. a second `ShowWindow(SW_SHOW)`, or consume the startup show mode on the hidden tray window when the icon starts.
  - Make sure a hidden first dialog doesn't stay behind as a stray window.
  - Check the other menu items open on the first click too.

## 3. Gaps and role changes

- **L13b: a gap recorded before the L13 fix never clears.**
  - The Windows 11 collector still says "Missing: batches 1-280 from ubuntu-server never arrived … ubuntu-server no longer keeps them, so they cannot be sent again", and `status` exits 4 for good.
  - Those batches went to the previous collector, and their events later arrived through it (L14).
  - Clear such a gap when the sender's batches say where its earlier batches went.
  - Give an administrator a recorded way to accept a known gap, e.g. `blackbox gaps accept ubuntu-server 1-280 "went to the previous collector"`. The next report shows it as accepted, with who, when and why, and it stops affecting the exit code.
- **AR3b (minor):** a standalone computer that became a sender made no `_final` report, though the 0.14 notes say it should. It forwarded its unsent standalone events instead, so nothing was lost. Either make the final report as described, or update the release notes and docs to describe forwarding, and say in setup which happened.

## 4. Small

- **UI13:** Audit health's section bar says "Antivirus · all current" while the table lists a system as "None found · Not checked". Count "not checked" in the bar.

## Done means

- Everything above is fixed with tests. TRAY1 needs a reproduction note, or an explanation if it can't be reproduced.
- The new rows in findings.md get a "Fixed in" entry.
- The version is bumped, with the IDs in the release notes.

Still to re-test live after this release: a fresh Windows 11 install (A13/A16/A17 noise), the SFTP outage end to end (L12), and the tray on the owner's own PC.
