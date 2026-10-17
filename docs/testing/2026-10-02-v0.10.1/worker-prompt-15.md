You're working on Blackbox (github.com/casea1/blackbox). 0.30.0 was tested live on 17 Oct 2026 (findings.md, "0.30.0 live test"). Prompt 14 (DET1b, LOG2) is confirmed fixed on both Linux and Windows, and PAGES1 works on real data. One sender bug must be fixed before Windows senders are rolled out.

## SEND2 (must fix): a stale SMB session stops a Windows sender, and setup says it works

`share.Connect` (internal/share/share_windows.go) treats `ERROR_SESSION_CREDENTIAL_CONFLICT` (1219) as success. On the rig:
- A sender's `share_user` changed from one account to another, and the old account was deleted.
- SYSTEM kept its old SMB session, and deliveries went on under it.
- When the collector rebooted, that session reconnected as the deleted account. Every scheduled run then failed for 3 days with "(The user name or password is incorrect.)", though `share_user` and the stored password were right.
- `install --yes` (run by an administrator) delivered all 296 waiting batches and said "Done", because it ran in the admin's own session. The next scheduled run (as SYSTEM) failed again.
- `net use \\SERVER\SHARE /delete` as SYSTEM fixed it at once.

What to change:
- On 1219, cancel the existing connections to that server (`WNetCancelConnection2` on the share and `\\SERVER\IPC$`, not forced if files are open) and connect again as `share_user`.
- If it still can't connect as `share_user`, say "already connected to SERVER as another account; …", not the logon error.
- Setup's delivery check: run the first send as SYSTEM (for example, start the scheduled task and wait for its result). Or say plainly that the check ran as the current user, and that the scheduled send is checked at its next run.
- **Tests:** 1219 followed by a cancel and a successful reconnect; 1219 that still fails gives the "another account" message. Use a fake for the mpr calls.

## DET5 (must fix): a continuing failed-logon run is one detection

One sender with old credentials gave 92 High "Possible password guessing" detections in one day, one per 15-minute window, all for the same account from the same address.
- Roll runs for the same account and source, with gaps under an hour, into one detection: first and last time, total count, and "still going at the end of the period" when it is.
- Say when the account doesn't exist on the target (4625 status/substatus 0xC0000064).
- When the account is or was a member of `Blackbox Senders`, or the source is a sender's, add "probably a sender with old or wrong credentials" and name the systems that are silent or late.
- **Tests:** 96 windows of 20 failures give one detection with the total; a real burst followed by a different account stays separate.

## Backlog

- **DET6:** setup's own `.blackbox-write-test-*` file in the reports folder, deleted by Blackbox-Setup during an upgrade, is a High "Blackbox's files changed". Ignore Blackbox's own write-test files.
- **CNT1:** the same report says 47 (Overview card), 51 (Needs attention) and 56 (fix-list) settings to fix; the Systems page says 23 for a system the fix list counts 25. Use one count, or label each one.
- **FIX1b:** `fix-list.html` is 1.2 MB for 3 systems, mostly OpenSCAP scripts. Fold them, or put them in a linked folder; print CAT I scripts only.
- **UPG1b:** `install --yes` printed no "New setting" line for `network` and left `network = ` blank. Write `lan` and say so, as the 0.29.0 notes describe.
- **DET1c:** an `rm` that failed with "No such file or directory" is called "(refused)". Keep "refused" for EACCES/EPERM.
- **UI23:** the Systems Status cell repeats the host name ("… on WIN11-TEST" in WIN11-TEST's row).
- The 0.29.0 release notes still say `99-blackbox.rules` (it is `zz-blackbox.rules`).

## Done means

- SEND2 and DET5 are fixed, with tests.
- The new findings rows get "Fixed in".
- The version is bumped.
- The release comment lists anything not verified live.
