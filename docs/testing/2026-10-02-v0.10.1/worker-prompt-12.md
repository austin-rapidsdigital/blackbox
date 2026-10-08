You're working on Blackbox (github.com/casea1/blackbox). 0.23.0 was checked live on 8 Oct 2026 (findings.md, "0.23.0 live check"). The per-sender inbox folders from #98 work, but they:
- take manual set-up (one account and one `inbox add` per computer);
- aren't in setup;
- don't help when senders share one delivery account, as setup suggests (`bbsend`);
- lose or double-import batches when a sender is moved (SEC1c);
- can be taken over before they're made (SEC1b).

**Owner decision (8 Oct 2026):** replace the per-sender folders with a **drop-only inbox and signed deliveries**. The goal is the same protection with nothing extra for the administrator to set up: no folders, no extra accounts, no migration step. The owner's network has about 30 computers, half Windows and half Ubuntu, with no domain, so assume senders may share one delivery account.

**Confirmed live in 0.23.0, don't regress:**
- refused files go to `rejected` with a `.why.txt` naming the writer, `status` exits 4, and importing carries on (SEC2);
- LNX1, LC2c, event 101 (LEDGER4), the settings check recorded at setup (UX10b), and `send --resend`;
- FIPS module on.

## 1. Drop-only inbox (must fix)

There is one inbox folder, as before 0.23. Senders can add files to it but can't list, read, change, rename or delete anything in it, their own files included.

- **Windows (NTFS, under the existing share):**
  - On the inbox folder, Blackbox Senders gets **Create files / write data** and Synchronize, on this folder only. It does not get List folder, Create folders, Read, Delete, Delete subfolders and files, or Change permissions.
  - New files inherit no Senders entry. Add `OWNER RIGHTS` with no rights, so the creator gets no implicit `WRITE_DAC`/`READ_CONTROL` on its own file.
  - The creating handle keeps the access it asked for, so the sender can write the file it just created and nothing afterwards.
  - Administrators and SYSTEM keep full control.
  - Check it: a sender account can create a file, but can't list the folder, open another file, overwrite, delete or rename its own file, or make a folder.
- **Linux SFTP collector:** the inbox directory is owned by root, group blackbox-senders, mode **1730** (sticky, group write and search, no read). A sender can create files but can't list the directory or remove anyone else's files. It can still remove its own. That's acceptable, because a removed batch is a signed sequence number that never arrives, and shows as a gap.
- **Sender writing without rename:** a sender can't rename, so the temp-then-rename approach is gone.
  - Write straight to the final name, with `O_EXCL` / `CREATE_NEW`.
  - Make each name unique: `HOST_SENDERID_SEQ_RANDOM.bbx`. A collision then means someone else made that file; retry under a new random part.
  - The sender can't check the inbox. A batch counts as delivered when it was written and closed without error; the collector's missing-batch list (`gaps`, `send --resend`) is the check.
- **Collector reading partial files:** a file whose signature doesn't verify yet may still be being written.
  - Skip it this run if it is less than 10 minutes old.
  - After that, refuse it into `rejected` as incomplete.
- **Setup and upgrade apply the ACL themselves** (collector install and upgrade). Remove the 0.23 per-sender folders:
  - import anything waiting in them, under the rules below;
  - remove the folders;
  - remove `blackbox inbox add`, saying in the release notes that it was replaced.
- **Tests:** an ACL test on Windows CI with a non-admin account (create works; list, read, delete, overwrite, rename and mkdir all fail), the Linux mode test, and partial-file handling.

## 2. Signed deliveries (must fix)

- **Sender key:**
  - At install or upgrade, each sender makes a signing key pair. Use Ed25519 if it's inside Go's FIPS 140-3 module boundary (FIPS 186-5 approves it); otherwise use ECDSA P-256. Check, and say which in the docs.
  - The private key lives in the data folder: Administrators/SYSTEM only on Windows, root 0600 on Linux. It never leaves the computer.
  - `blackbox status` on a sender shows `Signing key: SHA256:ab12…`. Setup's last screen shows it too, so an administrator can compare it with what the collector shows.
- **What is signed:** every delivery (batch, original-log archive, SCAP result). The signature covers:
  - the file's SHA-256;
  - the host name, sender ID and sequence number (for archives: host and period; for SCAP: host and file hash);
  - the time it was made.

  Put it in the file's trailer, or in a `.sig` written alongside it with the same unique name. A signature that doesn't verify against that host's key is refused into `rejected` with the reason.
- **Key pinning (trust on first use):**
  - The first signed delivery from a host the collector hasn't seen pins that host to that key.
  - The collector shows it once: a `status` line "New sender: ubu-ws-01 (key SHA256:ab12…, first seen 8 Oct 14:02)", and an Info row in the next report.
  - New config `new_senders = accept|hold`, default `accept`. With `hold`, a new sender's deliveries wait until `blackbox senders approve NAME`. Put it in setup as a checkbox, "Accept new computers automatically" (ticked).
- **Key changes** (a reinstall, a re-imaged computer, a restored data folder):
  - A known host delivering under a different key is **not imported**. Its files wait in `rejected/held`, and there's a High row and a `status` line: "ubu-ws-01 is now signing with a different key (SHA256:cd34…, was SHA256:ab12…). If that computer was reinstalled: blackbox senders rekey ubu-ws-01".
  - After `rekey`, the held files are imported.
- **The same key on two hosts** (a cloned computer with its data folder) is a High row. Neither host is merged into the other. `blackbox send --new-id` also makes a new key.
- **What this replaces:**
  - Host and sender-ID spoofing, forged `first_seq`, false former names and forged archives or SCAP: none can be made without the host's key. Keep the 0.23 checks as a second line, and keep the review tests.
  - SEC1b (squatted folders) and SEC1c (moving a sender between folders) go away with the folders.
- **Writer account:** keep recording which account wrote each file, but as information only. Signatures decide what is accepted.
- **Collector commands:**
  - `blackbox senders` lists each host with its key fingerprint, first seen, last delivery and signed/unsigned.
  - `blackbox senders approve NAME`, `blackbox senders rekey NAME` and `blackbox senders forget NAME` each write Application event 102 / journal, with who did it and why, as `reports accept` does.
- **In the report:**
  - Systems shows "Delivery: signed · key SHA256:ab12… since 8 Oct" on each system's page.
  - Overview's Needs attention shows new, changed or unsigned senders.
  - The Verified pop-up adds "All deliveries were signed by their computer's key".
- **Sender check:** a sender checks that its key file is still Administrators/SYSTEM only (Linux 0600 root) and says so in `status` if not.

## 3. Upgrade without losing data (must fix)

- **Unsigned deliveries for one release.**
  - The collector still accepts unsigned deliveries from a host that has **never** sent a signed one, marked "unsigned" in `status` and on the system's page. This covers senders not yet upgraded.
  - Once a host has delivered signed, an unsigned delivery claiming to be from it is refused (no downgrade).
  - `status` lists unsigned senders with "upgrade these to 0.24".
  - Config `require_signed = no|yes`, default `no` in this release, `yes` from the next.
- **Upgrade mid-stream:** a sender upgraded while it has batches waiting delivers its old unsigned batches and then signed ones, with no gap, no rejection and no double import. Keep each sender's import record (last number, missing list, the hashes behind "already imported") keyed by sender ID, independent of folder or signing state.
  - **Test:** a sender with unsigned batches waiting is upgraded and sends signed ones, and a 0.23 per-sender folder holds batches at the collector upgrade.
  - **The SEC1c case must pass:** batches 431-433 imported once, never listed as missing, and not imported again.

## 4. CLI2 (must fix): flags after subcommands

`blackbox inbox add NAME ACCOUNT --host COMPUTER` failed because flags stop being parsed at the subcommand. `inbox add` is going, but `gaps accept`, `reports accept`, `systems rename` and the new `senders …` commands must accept flags anywhere after the subcommand. Add CLI tests.

## 5. Small

- Setup's last screen on a collector: "Other computers send to C:\BlackboxInbox. Each one signs what it sends; new ones appear in blackbox status." Remove the per-folder wording.
- LEDGER4b: say "It held the only copy of that period's original logs" only for `logs-*.zip`.
- TZ1b: write `piece.json` and `archive.json` log ranges in UTC (`Z`) throughout.
- Don't list systems removed with `systems remove` in any sender warning.
- Docs: rewrite `docs/lan.md` "Each sender's own folder" as "How the inbox is protected" (drop-only folder, signatures, first-use pinning, key changes, unsigned senders during an upgrade). Update `security.md`.

## Done means

- Everything above is fixed, with tests. The Windows ACL test runs on CI with a non-admin account.
- A 30-sender test: one shared delivery account, 15 Windows and 15 Linux (simulated), one cloned sender, one reinstalled sender and one unupgraded sender. Each is handled as described, with no lost or doubled batches.
- The new findings rows get "Fixed in".
- The release notes explain the change from 0.23's folders.
- The version is bumped.

Still to test live after this release: the drop-only ACL on the real collector with the Ubuntu SMB sender; a reinstalled sender (key change); an unupgraded sender during the upgrade; and the per-sender folder clean-up on the test collector.
