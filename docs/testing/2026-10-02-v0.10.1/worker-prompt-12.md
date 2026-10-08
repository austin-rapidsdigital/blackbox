You're working on Blackbox (github.com/casea1/blackbox). 0.23.0 was checked live on 8 Oct 2026, on the Windows 11 collector, the Ubuntu 26.04 sender and the Server 2025. The details are in `docs/testing/2026-10-02-v0.10.1/findings.md`, section "0.23.0 live check". This is a short list. Do it before or alongside prompt 11 (the redesign).

**Confirmed live, don't regress:**
- per-sender folders, and the sender finding its folder;
- refused files in `rejected` with the writer named, and `status` exit 4;
- LNX1 (Ubuntu 26.04 SSH logons, joined with the key fingerprint);
- LC2c (small-log clear);
- event 101;
- the settings check recorded at setup;
- `send --resend` recovery;
- FIPS module on.

## 1. SEC1b (must fix, High): a sender can prepare another computer's folder

The inbox root still gives every sender account Modify. A sender can therefore `mkdir` a folder in the root and put files in it. `blackbox inbox add` then adopts that folder:
- the owner stays the sender's account;
- that sender can still list the folder;
- files planted earlier are read at the next run as that folder's computer.

The collector records which account wrote each file but never checks it.

- **`inbox add` must refuse an existing folder it didn't make**, or: move its contents to `rejected` with a note, set the owner to Administrators, and re-apply the ACL. Say which it did.
- **On import, refuse any file in a sender folder whose owner isn't that folder's account** (or Administrators/SYSTEM). Raise it as a High row naming the writer. On Linux SFTP, use the file's uid.
- **Don't let senders create folders in the inbox root:** grant Blackbox Senders create-files but not `FILE_ADD_SUBDIRECTORY` there. Check this doesn't stop the shared-folder senders still on 0.22 from delivering.
- **Tests:** a squatted folder with a planted well-formed batch is not imported, and is raised. Also a Windows ACL test for the root.

## 2. SEC1c (must fix): moving a sender to its own folder

- **The batch in flight is lost.** A batch delivered to the shared folder before the sender's folder existed is refused afterwards ("delivers through its own folder"). Accept it if it was written before the folder was made (by file time), or by the same account the folder is for.
- **False gap and double import.** Batches 431-433 were imported from the shared folder. After the switch, `gaps` listed them as missing, and resending imported them a second time. Keep each sender's import record (last number, missing list, the hashes behind "already imported") across the move to its own folder.
- **Test:** a sender switching folders mid-stream, with one batch in the shared folder at the switch. The result should be no gap, no rejection, and no double import.

## 3. CLI2 (must fix): the documented `inbox add` syntax fails

`blackbox inbox add NAME ACCOUNT --host COMPUTER` gives the usage error, because flags stop being parsed at `add`. It's what the docs, the release notes and the command's own usage text show. Parse flags anywhere after the subcommand, check `gaps accept`, `reports accept` and `systems rename` for the same problem, and add CLI tests.

## 4. Small

- **SEC1d:**
  - Make `BLACKBOX-SENDER.txt` read-only to the sender (its account could append to it), or don't rely on its contents.
  - Don't list systems removed with `systems remove` as "still delivering into the shared inbox folder".
  - Setup and the collector upgrade should say how to give senders their own folders, instead of "Other computers can now send to this collector's inbox".
- **LEDGER4b:** say "It held the only copy of that period's original logs" only for `logs-*.zip`.
- **TZ1b:** write `piece.json` and `archive.json` log ranges in UTC (`Z`) throughout.

## Done means

- SEC1b, SEC1c and CLI2 are fixed with tests.
- The new findings rows get "Fixed in".
- The version is bumped.

Still to test live after this release: the per-sender folder over SFTP (Linux collector path), and a sender upgraded from 0.21 straight to the new version.
