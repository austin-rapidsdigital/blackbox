# Several computers: VMs and LANs

One computer, the **collector**, produces reports that cover itself and
every computer that sends to it. The other computers keep collecting their
own logs every hour and copy what they collect into the collector's
**inbox**, a folder on the collector.

![A combined report's Systems page](images/lan-systems.png)

```
 Linux VM (VirtualBox) ──shared folder──┐
 Ubuntu PCs ────────────Windows share───┼──►  Collector: C:\BlackboxInbox  ──►  one report for all of them
 Windows PCs ───────────Windows share───┘
```

- **Nothing listens on the network.** Computers copy files into a folder,
  which can be a VirtualBox shared folder or an ordinary Windows share. No
  ports are opened, and it works with or without a domain.
- **A computer that is off or cut off loses nothing.** Its data waits on
  it and is sent when the collector can be reached. A VM that is only
  switched on for a few minutes catches up each time.
- **Gaps are reported.** Each delivery is numbered and checksummed. If one
  goes missing or is damaged, or a computer stops sending, the report says
  so. See [What the report shows](#what-the-report-shows).
- **Small.** Only the security events Blackbox keeps are sent, compressed,
  and only what is new. Expect tens of kilobytes per computer per hour.
  Once a day a computer also sends a zip of its original logs, typically
  a few MB for Windows (see [Original logs](reports.md#original-logs)).

## Choosing a role

The installer's first question sets the role:

| Choose | For | Produces reports? |
|---|---|---|
| **On this computer** | A standalone computer | Yes, about itself |
| **Send to a collector** | A Linux VM, or a LAN workstation | No, its events appear in the collector's reports |
| **This is the collector** | The PC or server the ISSO reviews reports on | Yes, about itself and every sender |

A computer is one or the other: it sends to a collector, or it is one.

**Set up the collector first.** Senders check that the collector's inbox is
there before they use it.

## Scenario 1: one air-gapped PC with a Linux VM

The Windows PC is the collector. The VM sends through a VirtualBox shared
folder, so no networking is needed.

**On the Windows PC:**

1. Run `Install.cmd` and choose **This is the collector**.
2. Accept the inbox folder, `C:\BlackboxInbox`.
3. Answer **yes** to "Will virtual machines on this PC send to it?" and
   give the Windows account that runs VirtualBox. That account is added
   to the local group **Blackbox Senders**, which may write to the inbox.
   It takes effect the next time that account signs in.
4. Answer **no** to sharing it on the network.

**In VirtualBox**, with the VM powered off:

1. Open **Settings → Shared Folders** and add a folder.
2. Set **Folder Path** to `C:\BlackboxInbox`.
3. Set **Folder Name** to `BlackboxInbox`.
4. Tick **Auto-mount**. Leave **Read-only** unticked.

The VM needs the VirtualBox Guest Additions. They are on the Guest
Additions CD image that comes with VirtualBox, so no internet access is
needed.

**In the VM** (Ubuntu or AlmaLinux):

1. Run `sudo ./install.sh`.
2. Choose **Send to a collector**.
3. Setup finds `/media/sf_BlackboxInbox` and offers it as the default.
   Press Enter.

Done. The VM's events appear in the Windows PC's next report. Its
Systems page lists both computers.

## Scenario 2: LAN workstations that host Linux VMs

Every computer sends straight to the LAN collector (scenario 3), VMs
included:

- **The workstation** is a sender, like any other LAN computer.
- **Its VM** is a sender too. It reaches the collector's inbox over the
  network: the Windows share, or an SFTP mount (see
  [Other ways to reach the inbox](#other-ways-to-reach-the-inbox)). The VM
  therefore needs a network adapter that can reach the collector, for
  example a bridged adapter.

Your script that powers the VMs on for the scheduled job keeps working. A
VM does not have to be on at a particular time:

- The Blackbox timer runs 5 minutes after boot and catches up any runs it
  missed while the VM was off.
- A Linux sender also sends when it shuts down cleanly (the
  `blackbox-shutdown.service` unit), so a VM powered off with an ACPI
  shutdown delivers its last events on the way down. A VM that is
  powered off hard does not; to be sure, run `sudo blackbox send` in the
  VM from your script before stopping it.

## Scenario 3: a LAN with a Windows collector

**On the collector** (a Windows PC or Windows Server):

1. Run `Install.cmd` and choose **This is the collector**.
2. Answer **yes** to "Share it on the network". Setup then:
   - shares `C:\BlackboxInbox` as `\\COLLECTOR\BlackboxInbox`
   - gives the local group **Blackbox Senders** permission to write to
     it (and nobody else)

Senders sign in to the share with an account on the collector. Choose how:

- **Workgroup (no domain):** create one local account for senders and add
  it to the group. Use a strong password, and follow your password policy.

  ```
  net user bbsend * /add
  net localgroup "Blackbox Senders" bbsend /add
  ```
- **Domain:** add `DOMAIN\Domain Computers` (or a group of the sending
  computers) to **Blackbox Senders**. Windows senders then need no
  password: they sign in as their computer account.

**On each Windows sender:**

1. Run `Install.cmd` and choose **Send to a collector**.
2. Enter `\\COLLECTOR\BlackboxInbox`.
3. Enter the account and its password. On a domain, leave the account
   blank.

The password is stored encrypted with Windows DPAPI, and only
Administrators and SYSTEM can read it. Setup checks the share straight
away.

**On each Ubuntu or AlmaLinux sender:**

1. Install the SMB client if it is not already there. It is on your
   installation media:
   - Ubuntu: `sudo apt install cifs-utils`
   - AlmaLinux: `sudo dnf install cifs-utils`
2. Run `sudo ./install.sh` and choose **Send to a collector**.
3. Enter `//COLLECTOR/BlackboxInbox`, then the account and its password.

Setup stores the account in `/etc/blackbox/share.cred`, readable by root
only. It also creates a systemd mount unit that mounts the share for
Blackbox before each run. Files on the share are root-only and cannot be
run.

**FIPS mode (STIG-hardened Ubuntu Pro, AlmaLinux).** With
`/proc/sys/crypto/fips_enabled` set to 1, the kernel refuses the NTLM
sign-in that SMB shares use, so the mount fails. Setup detects this and
says so. Use an SFTP (sshfs) mount instead, which works in FIPS mode; see
[Other ways to reach the inbox](#other-ways-to-reach-the-inbox).

If the collector cannot be reached during setup, you can still continue.
The data waits on the sender until the collector can be reached.

## Other ways to reach the inbox

A sender needs only a folder it can write to that holds the collector's
inbox. Any way of mounting the inbox works:

- a VirtualBox shared folder
- an SMB share (set up by the installer)
- an SFTP mount
- an NFS mount

Blackbox checks for the collector's `BLACKBOX-INBOX.txt` marker before
every delivery, so a mount that is down is never mistaken for the inbox.
The data simply waits until the mount is back.

**SFTP (sshfs) from a Linux sender.**

1. On the Windows collector, turn on the **OpenSSH Server** optional
   feature. On an air-gapped system, install it from the Features on
   Demand media.
2. Give an account (the same one as for SMB is fine) write access to the
   inbox through **Blackbox Senders**, and use key-based sign-in.
3. On the Linux sender, install `sshfs` from the installation media and
   mount the inbox at boot. For example, in `/etc/fstab`:

   ```
   bbsend@COLLECTOR:/C:/BlackboxInbox  /mnt/blackbox-inbox  fuse.sshfs  _netdev,reconnect,IdentityFile=/root/.ssh/blackbox,ServerAliveInterval=15  0 0
   ```

4. Run `sudo ./install.sh`, choose **Send to a collector**, and enter
   `/mnt/blackbox-inbox`.

The installer and CI test VirtualBox shared folders and SMB shares. An
SFTP mount goes through the same checks, but its setup is yours.

## Day to day

**Reviewing.** Open the collector's reports as usual. Start with the
**Systems** page:

- every computer, with its last collection, event counts, high-severity
  events and audit settings
- anything wrong is listed first
- selecting a computer's name filters every event table in the report to
  it; the **All systems** menu above each table does the same

**Checking a computer is working.** Run `blackbox status` as an
administrator or root. It shows:

- the computer's role and its last collection
- on a sender: when it last delivered, and anything waiting to be sent
  (with the reason, if sending failed)
- on a collector: what is in the inbox, and every computer it has heard
  from

```
Blackbox 0.2.0 on WS-07

  Role:             collector (reports on this computer and the computers that send to it)
  Last collection:  2026-10-02 14:05 (12 minutes ago)
  ...
  Inbox:            C:\BlackboxInbox — OK; 0 batches waiting to be imported

Systems (3)
  NAME                 OS       LAST COLLECTION    LAST RECEIVED      NOTE
  ubu-ws12             linux    2026-10-02 13:58   2026-10-02 14:05
  WS-07                windows  2026-10-02 14:05   -                  this computer
  WS-09                windows  2026-09-26 09:00   2026-09-26 09:05   SILENT: LAST COLLECTION 6 DAYS AGO
```

**Adding a computer.** Install Blackbox on it and choose **Send to a
collector**. It appears on the Systems page after its first collection.

**Retiring a computer.** On the collector, run
`blackbox systems remove NAME`. It stops being listed and reported as
silent. Its events stay in earlier reports, and it is listed again if it
ever sends again.

**Changing where a computer sends.** Run the installer again. It shows the
current settings as the defaults. From a script, run
`blackbox config set send_to \\NEWCOLLECTOR\BlackboxInbox` as an
administrator. The share password is read from `BLACKBOX_SHARE_PASSWORD`.

## What the report shows

The report points these out, both on its Overview and Audit health pages
and in `summary.json`:

| Situation | What the report says |
|---|---|
| A computer sent nothing in the report period | "The audit trail is not complete": the computer, its last collection, and that it may be off or unable to reach the collector |
| A computer has not collected for more than 36 hours | Flagged on the Systems page |
| A delivery never arrived (for example, deleted from the inbox) | Which batches from which computer are missing |
| A computer's clock is ahead of the collector's | The computer and by how much. Event times from it may be wrong |
| Events arrived after the report they belong to | Included in the next report, marked **Late** |
| A delivery is damaged or altered | It is set aside in `inbox\rejected` and logged. The gap it leaves is reported |

## Troubleshooting

Run `blackbox status` on the sender first: it shows the last error.

| Symptom | Likely cause |
|---|---|
| "collector inbox not available" | The share or shared folder is not reachable. Check the collector is on, the VM's shared folder is set up with Auto-mount, and the Linux mount: `systemctl status var-lib-blackbox-collector.mount` |
| "is not a Blackbox inbox" | The folder is reachable, but the collector has not been set up yet, or the path is wrong. Run the installer on the collector first |
| Access denied on a Windows sender | The account is not in **Blackbox Senders** on the collector, or its password changed. Run the installer on the sender again to update it |
| The VM cannot write to `/media/sf_BlackboxInbox` | The Windows account that runs VirtualBox is not in **Blackbox Senders**, or has not signed in again since it was added |
| A computer shows as silent | It was off, or could not reach the collector. Its own `blackbox status` says which |

## How it works

This section is for reviewers.

- **Batches.** After each collection, a sender writes what is new since its
  last batch to a numbered file in its own outbox. The file is compressed
  JSON lines with a SHA-256 checksum and a closing record, so a damaged or
  cut-short file is detected. It then copies waiting batches, oldest
  first, into the inbox:
  - under a temporary name first, then renamed, so the collector never
    reads half a file
  - only into a folder that holds the collector's `BLACKBOX-INBOX.txt`
    marker, so a share that is not mounted (an empty local folder) is
    never mistaken for the collector
- **Import.** Each time the collector collects, it imports every complete
  batch in each sender's order. It records each batch number and skips
  one it already has, so a batch delivered twice counts once. It then
  deletes the file from the inbox.
- **Crash safety.**
  - Before appending a batch, the collector notes its data files' sizes.
    If it stops part way, the next run cuts the files back and imports
    the batch again.
  - A sender only marks data as batched after the batch is safely on its
    own disk.
- **Received events count from their arrival.** An event is treated as
  collected when it reached the collector, so it lands in exactly one
  report. If it arrives late, it goes in the next report, marked Late.
- **Identity.** Each sender has a random ID created when it first sends.
  A computer that is reinstalled or renamed starts a new sequence instead
  of looking like a gap.
