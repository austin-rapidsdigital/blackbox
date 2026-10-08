You're working on Blackbox (github.com/casea1/blackbox). This is a **UI/UX redesign of the report**, chosen page by page by the owner on 8 Oct 2026. For each page there were three mockups: a new layout, a new layout with new features, and the current layout simplified. The chosen mockups are in `docs/testing/2026-10-02-v0.10.1/redesign-2026-10-08/` (PNG, 1440 px).

The mockups use a made-up 30-computer network: 11 servers, 19 workstations, 15 Windows, 15 Ubuntu. It has **local accounts only, no domain**: 50–100 accounts on each system, about 20 in use. The redesign must stay readable at 30 systems and work at 100+. Keep the existing look (fonts, colours, panels, icons), the static offline report, and everything that is computed today. This is a layout and wording change, plus the few new pieces of data called out below.

Do worker prompt 10 first, or alongside. Where this prompt changes a page prompt 10 also touches (UI19 labels, UI20, UI21 wording), do it once, the new way.

## Rules across every page (owner)

- **Short and simple.** A summary list shows a title, a system and a time (or a count), never the full explanation. The detail lives one click away (a detection opens on Detections at that detection). Apply this everywhere: e.g. Health's antivirus line becomes "Antivirus out of date · 5 systems · definitions over 7 days old", not the current sentence.
- **No duplicated data:** one place per fact.
  - Settings problems are on Audit health only.
  - Missing systems and logs cleared are on Overview, Systems and Detections, not as Audit health gaps.
- **Group by servers and workstations** wherever systems are listed. Classify an OS as server or workstation as UX10 does.
- **Problems first, quiet things folded.** "22 more systems with no problems (14 with warnings, 8 all OK)", "+14 more users with no privileged actions or detections · show".
- **One page header:** breadcrumb line, title, and only the page's own buttons on the right (usually Export CSV). The period, Verified and All reports move to the sidebar's report card.
- **Times:** local, with the zone shown once per page. Event detail shows local and UTC.

## Sidebar (all pages): image 01

- **Groups:**
  - **Review:** Overview, Detections, Search.
  - **Who and what:** Systems, People.
  - **Evidence:** Audit health, Original logs.
  - **Events by kind:** Privileged activity, Audit integrity, Logon activity, Other security, PowerShell, with counts.
  - **More:** Inventory, Trends.
- The groups are always open, with no fold toggles.
- **Brand line:** "Blackbox" with the network name under it.
- **Report card at the bottom:** report type, period, systems, generated time, a "✓ Verified · files match manifest" line that opens the Verified pop-up (14), and "All reports →".
- **No search box and no review progress** (the owner turned both down).

## 1. Overview: image 01 (layout A)

- **Summary line:** "Needs review: 4 high detections, 2 systems not reporting", with one short sentence of the most serious facts. Green "Nothing needs review" when that's the case.
- **Number strip, one row:**
  - Detections (high · medium);
  - Systems reporting (n / N, "2 silent");
  - Events (privileged · logons);
  - Audit settings (n / N matching the STIG · settings to fix).
- **Detections:** up to 8, high first then newest. Each is one line: title, one short reason, system, time. Then "All 11 detections (3 more medium) →". Clicking a line opens Detections at it.
- **Needs attention:** one line per kind:
  - a label, a short reason, and a system count, naming the systems only when there are one or two;
  - then "Fine: Reports on time · No Security or audit-log events lost · 26 systems reporting normally".
- **Activity this period:** events per hour, full width and short. Windows and Linux are stacked in two colours, with a red dot on hours that have a detection. Clicking a bar opens Search for that hour.
- **Systems at a glance:**
  - only systems with a red check, grouped Servers / Workstations;
  - the six check cells: Reporting, Logs intact, Settings, Antivirus, Orig. logs, SCAP;
  - events per system;
  - then "22 more systems with no problems… All 30 systems on the Systems page →".
- **Removed from today's Overview:**
  - the four large tiles;
  - the coloured health bar with its legend;
  - the "1 of 3 systems" column;
  - "No new admins, policy changes…";
  - "What changed" (it is on Trends).

## 2. Detections: image 02 (A)

- **Filter bar:** severity (All / High / Medium with counts), System, Person, Servers / workstations.
- **Left:** a list grouped High · n / Medium · n. Each line has a title plus system and time.
- **Right, the selected detection:**
  - title and severity chip;
  - **one plain sentence** of what happened;
  - four facts: System (OS · role), Person (group), When (with zone), Record (log, event ID, record number);
  - one line on why it matters and what the original logs still hold.
- **What happened:** the events about 10 minutes either side on that system for that person, with the detection's own events highlighted. This replaces today's separate "What happened" and "Events" panels, which repeat rows. Buttons: "Open in Search (±10 min)" and "Everything <person> did".
- **Related this period:** other detections with the same person or system, one line each.
- **Not in this release:** triage status, ATT&CK and "seen before" on detections.

## 3. Search: image 03 (A)

- **One search box** that searches every field, with dropdowns: Kind, Person, System, Servers / workstations, Severity, When. The eight "Common searches" tiles become one "Common searches ▾" dropdown.
- **Left:** field counts for the current results (System, Event, Severity), with bars. Click to filter, Alt-click to exclude.
- **Right:** a header count line ("64 events · 5 systems · 3 high"), events per hour, then the results.
  - Columns: Time, System, Person, Event, Details, ID, Severity.
  - High rows are tinted.
  - "Group by ▾" sits above the table, and paging is "Show 50 more".
- No field syntax, no saved searches and no pivot grid for now.

## 4. Systems: images 04 (list) and 05 (one system) (A)

- **List:** filter bar with "Find a system", All / Problems / Warnings / OK with counts, OS and Role.
  - **One table grouped Servers · n / Workstations · n**, worst first.
  - **Columns:** a status dot and name; OS; the six check cells; Events; Det.; Last seen.
  - **No "Why" column** (the owner removed it).
- **One system:** breadcrumb "Systems › Servers › <name>", plus "Search this system" and Prev / Next.
  - **Header:** the problem as one chip, then OS · role · model · which collector it sends to.
  - **Six facts:** events, detections, last collection and its interval, audit settings (n to fix of N), SCAP, original logs size.
  - **Collection strip:** one cell per expected collection in the period, with a red mark at a log clear and grey for a missed collection. This needs the per-run records (runs-*.jsonl) carried into the report data.
  - **Then:**
    - Checks, one short line each, with "Audit health →";
    - Detections on this system;
    - activity per hour;
    - Who was active (account, role, count);
    - Events by kind.

## 5. People: images 06 and 07 (current list + A detail, for local accounts)

There is no domain here, so the same person has a separate local account on each system. Today `personKey` already merges `HOST\jlee` and `jlee` across systems, and only active accounts are listed. Keep both, and add the following.

- **Left list** (today's simple list, restyled):
  - "Find a person or account", and All / Detections / Admins with counts;
  - grouped Administrators · n / Users · n / Shared and service accounts · n;
  - each name has one sub-line: "admin on 9 systems", "3 systems", or "built-in, Linux · on 15 systems", plus a detection count badge;
  - **footnote:** "Same name on several systems = one row (e.g. jlee on 9). 1,768 other local accounts on the 30 systems were not used this period: see Inventory →".
- **A person:**
  - "Local account on 9 systems · administrator on all 9 · used on 5 this period", and a detection chip;
  - six facts: systems used (of N with this account), logons (with how many Remote Desktop / SSH), failed logons, privileged actions, after hours, detections;
  - **Where and when:** one lane per system used, showing sessions across the period with red marks at detections;
  - **Notable actions:** high and medium actions, one line each, with "all N in Search →";
  - **Accounts named <name>:** one row per system's account (`SRV-DC02\jlee`), with rights, logons this period and last use. Then "+4 systems where jlee exists but wasn't used" (from inventory), and a one-line note that same-name local accounts are shown as one person and a different spelling is not merged.
- **A shared or built-in account** (root, Administrator, and any account on many systems that `person()` treats as a person, such as a service account):
  - labelled "Shared built-in account · a separate account on each of N systems · not one person";
  - **Who acted as <account>:** split by the person who ran sudo / su / RunAs (Blackbox already ties sudo to the person), scheduled jobs and services, and direct logons (console or SSH), each with systems and count;
  - a box that says plainly whether anyone logged on as root/Administrator directly;
  - a Where and when lane chart.
- **New config, optional:** `people_aliases`, e.g. `blackbox config set people_aliases "jlee=j.lee,jlee2"`, to merge spellings across systems. Show the merge in the "Accounts named" table.

## 6. Audit health: image 08 (A)

- **Four cards:**
  - Audit settings match the STIG (n / N, a green/amber meter, "140 settings to fix on 22 systems");
  - SCAP (latest score, open CAT I and systems, not scanned in 30 days);
  - Antivirus (n / N current);
  - Logs (systems that overwrote events, and "0 Security/audit lost").
- **Tabs:** Settings to fix (n) · By system (N) · SCAP (n CAT I) · Antivirus (n) · Log sizes (n).
- **Settings to fix (default):** one row per setting, ordered by how many systems it affects.
  - **Each row:** severity dot; the setting ("Credential Validation: Failure") with OS and "without it the report misses: Failed logons"; the STIG ID(s) per OS (or "Blackbox's advice", per COMP2 in prompt 10); "9 systems".
  - **Expand a row** for the system names as chips, and the fix path with "One GPO on the OU fixes all 9".
  - Shows the top 8, then "12 more settings, each on 1–3 systems · Show all 20".
- **By system:** today's grid, grouped Servers / Workstations.
- No trend chart, POA&M or copy-command for now.

## 7. Original logs: image 09 (A)

- **Four cards:** logs in this report (n / N, "2 systems sent nothing"), Complete, With a gap ("1 log cleared · 3 PowerShell overwrites"), and Checked ("all 1,344 files match their SHA-256 · 3.1 GB").
- **One table grouped Servers / Workstations**, with gaps and missing first, and an All / Gaps and missing switch.
  - **Columns:** System; Status chip (Complete / Gap / Missing); a short Note ("Security log cleared 14:22; events before it kept up to 14:15"); Inside ("5 .evtx · 96 pieces" / "audit.log · 96 pieces"); Size; File.
- **"Giving these to an assessor" box** with three steps: `sha256sum -c manifest.sha256` or `blackbox verify`; open `.evtx` in Event Viewer or `ausearch -if` on audit.log; each zip's archive.json. Put the same text in a `README.txt` in each scheduled report folder (ASSESS1).

## 8. Events by kind: image 10 (A)

- Each of the five pages (Privileged activity shown) **is Search with the Kind filter preset**: the same box, filters, counts, chart and table.
  - Counts: Person, System, Kind.
  - Columns: Time, System, Person, Command or action, Severity.
- Clearing the Kind chip gives the full Search.
- **Remove** each page's own chart, Top people and Top systems panels.
- Sort high and medium first, then newest.
- Folding routine commands was not chosen.

## 9. Inventory: image 11 (current layout, with drive serials)

- **Left:** "Find a system or serial", and the system list grouped Servers · n / Workstations · n, each with its OS.
- **Right, the selected system:**
  - name; OS · role · model; Serial; Memory; Accounts (n, with administrators and how many were used this period).
  - **Drives table:** Model, Type (NVMe · SSD / SATA · HDD / USB · removable), **Serial number**, and a Note ("internal", or "seen 7 Oct 10:18 · not connected now" for a removable drive). Everything except "seen …" comes from `inventory.Drive` (Model, Serial, Size, Interface, Media), which is already collected. "Seen …" comes from the USB events.
  - **Accounts:** five shown (name, admin/user, disabled, last used), with "N more · Show all".
- The search finds a system by a drive serial too.
- **Export CSV:** one row per drive (system, model, type, size, serial), and one row per account.

## 10. Trends: image 12 (B)

- **Range switch:** 4 / 8 / 12 weeks. **Exports:** Export CSV, and Monthly summary (PDF), which can be the print view of this page.
- **Six small charts, one bar per calendar week:** detections, failed logons, privileged actions (people), systems matching the STIG, events lost to rollover, after-hours admin sessions.
  - Each shows this week's number and "usual N" (the median of the earlier weeks).
  - This week's bar is red when worse than usual, green when better, blue otherwise.
- **Biggest changes this week:** severity dot, system or person, measure, usual, this week, and a short why (e.g. "SSH guessing from 203.0.113.50 on 7 Oct").
- **Detections by system, by week:** a heat grid of systems with any detection in the range ("23 others had none · All 30").
- **New this week:** never seen in the range.
  - **Kinds:** a new admin (account and system); a new account; a new logon path (person → system, how); a new source address (with what it did); a new service; a new USB device.
  - **Data needed:** this needs each scheduled report's summary to keep the sets it compares, e.g. `summary.json`: admins per system, accounts, person→system pairs, source IPs, services and USB IDs. Read them from earlier reports' summaries, as the weekly counts are read today.

## 11. All reports (index.html): image 13 (A)

- **Four cards:** latest report (high · medium, Open →), next report (when, and what it covers), reports checked ("1 changed · 39 OK · 1 accepted as deleted · checked daily", from the ledger), and how many reports and GB are in the folder.
- **One table grouped by month**, newest first.
  - **Report column:** the date, with Latest / Manual chips and the manual report's reason.
  - **Other columns:**
    - Notes ("2 silent", "logs-ubu-ws-04.zip missing");
    - Systems (28/30), Events, High, Medium;
    - Original logs (size);
    - Check (✓ OK / Changed / Accepted, from the ledger).
- **Filters:** All / Scheduled / Manual / With high / Problems. Then "22 older reports · Show older".
- No calendar or "Kept for" column for now.

## 12. Pop-ups: images 14–16

- **Verified (14), the current pop-up, shortened.** Opens from the sidebar card.
  - The title: "This report has not been changed".
  - **Three checks:** report files match the manifest; n original-log zips checked; no gap since the previous report.
  - Then "Check it yourself: `blackbox verify`".
  - If any check fails, the title says so in red, and the failing check is first with its file name.
- **Export (15, A):** a menu with two parts.
  - **This page:** what the current page shows, as CSV ("Detections shown (11)").
  - **Whole report:** Summary (PDF/print), All events (n) CSV, Systems and drives CSV (with drive serials), Audit settings to fix CSV, Open SCAP findings CSV, Open the report folder.
  - Every CSV time carries its zone (ASSESS1).
- **Event detail (16, B):** a side panel that opens from any event row (Search, Events by kind, Detections' timeline).
  - **Header:** a breadcrumb ("Search › event · Security 4688"), the event in plain words, a severity chip, and "part of the detection <title> →" when it belongs to one.
  - **Facts:**
    - When (local and UTC, to the millisecond);
    - System (OS);
    - Person (`HOST\account`, rights);
    - Program; Command;
    - Started by (with the session it came from);
    - Outcome.
  - **Original record:** `logs-<host>.zip › <file>.evtx`, record n. This is the exact export piece and record number, so an assessor can find it (AR8/AR9 make this complete).
  - **Around it on <system>:** about four events either side, with this one highlighted.
  - **Context:**
    - Seen before ("never on SRV-DC02 in 30 reports", from earlier summaries as in §10);
    - ATT&CK (a static map from action to technique, e.g. log_cleared → T1070.001; leave it blank when there's no clear mapping);
    - "Same command: n other systems this period".
  - **Buttons:** Everything <person> did; ±10 min on <system>; Copy for a ticket (plain text: time with zone, system, person, what, record); Raw record ▾.
  - The raw record's fields are shown in the panel as today.

## Done means

- Every page matches its image at 1440 px. It also works at 1280 px and at 390 px (phone: one column, sidebar collapses) with no horizontal page scroll.
- It passes axe-core with no critical or serious issues (prompt 10 UI19).
- **Tested with a generated 30-system report** (15 Windows, 15 Linux, local accounts only, 50–100 accounts each, one root and one Administrator per system), plus today's 3-system data. Check the following, with tests:
  - the people merge;
  - the shared-account split;
  - drive serials in the Inventory view and CSV;
  - Trends' "New this week".
- `docs/reports.md` is updated with the new page descriptions, and its screenshots are replaced.
- The version is bumped, with "Report redesign (UI-R1)" in the release notes.
