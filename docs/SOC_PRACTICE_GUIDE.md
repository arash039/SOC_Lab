# SOC Skills Practice Guide — Splunk + attack_data

**Goal:** Build repeatable SOC muscle memory — data exploration, detection tuning, alert triage, threat hunting, and reporting — using a local Splunk instance and real attack data from `splunk/attack_data`.

**Current lab state (already set up):**
- Splunk running in Docker at `http://localhost:8000`
- Index `attack_data` created
- MITRE technique **T1003.001 (Credential Dumping / LSASS)** replayed into `index=attack_data` (~7,736 events)
- Python venv at `/home/arash/Desktop/VibeCodes/splunk/attack_data/venv`
- `bin/run_escu_detections.py` ready to run Splunk's own ESCU detections against your data

---

## How to use this guide

Work through the phases in order. Each phase has:

1. **Objective** — what you're practicing
2. **Commands / SPL** — copy-paste ready
3. **What to look for** — the learning outcome
4. **Validation** — how you know you did it right

Treat every search like a real alert: document your findings, write down false positives, and note what you'd escalate.

---

## Phase 0: Verify your lab is ready

Run this from your host terminal:

```bash
cd /home/arash/Desktop/VibeCodes/splunk/attack_data
source venv/bin/activate

export SPLUNK_HOST="127.0.0.1"
export SPLUNK_HEC_TOKEN="c1aa30d0-c5a5-43cc-8ee3-329a5253565a"
export SPLUNK_USERNAME="admin"
export SPLUNK_PASSWORD="S0cPractice!2026"
export SPLUNK_PORT="8089"
export SPLUNK_VERIFY_SSL="false"

# Confirm Splunk is reachable
curl -sk -u "${SPLUNK_USERNAME}:${SPLUNK_PASSWORD}" "https://localhost:8089/services/server/info?output_mode=json" | python3 -m json.tool | head -20
```

Expected: Splunk version, license, and server details.

Open Splunk Web: **http://localhost:8000** → login `admin` / `S0cPractice!2026`.

---

## Phase 1: Data familiarization

**Objective:** Learn to navigate an unfamiliar dataset, identify what log sources exist, and understand the field structure.

### 1.1 Confirm data landed

In Splunk Web → **Search & Reporting**:

```splunk
index=attack_data
| stats count as total_events by sourcetype
| sort -total_events
```

**What to look for:** You should see `XmlWinEventLog` (~7,721 events) and `crowdstrike:events:sensor` (~15 events). If counts are 0, wait 30 seconds for indexing and re-run.

### 1.2 Identify the sources

```splunk
index=attack_data
| stats count by source
| sort -count
```

**What to look for:** You'll see Windows Security event log sources, Sysmon operational sources, and CrowdStrike sources. This tells you which telemetry the attack generated.

### 1.3 Look at raw events

```splunk
index=attack_data sourcetype=XmlWinEventLog
| table _time, host, source, EventCode, ProcessName, ProcessCommandLine, User, Dest, ParentProcessName
| sort -_time
| head 100
```

**What to look for:** Common Windows event codes:
- `4688` — A new process has been created (process execution)
- `1` / `Sysmon Event ID 1` — Process creation (Sysmon)
- `10` / `Sysmon Event ID 10` — Process accessed (potential LSASS open)
- `4656` / `4663` — Handle to an object was requested (LSASS handle)

**Validation:** You see a mix of event codes and process names, not just one sourcetype.

---

## Phase 2: Understand the attack scenario

**Objective:** Connect the raw logs to the real-world technique (MITRE T1003.001).

### 2.1 Read the scenario metadata

Open this file in a text editor:

```
/home/arash/Desktop/VibeCodes/splunk/attack_data/datasets/attack_techniques/T1003.001/atomic_red_team/atomic_red_team.yml
```

Key facts:
- **Technique:** T1003.001 — LSASS Memory (Credential Dumping)
- **Environment:** `attack_range`
- **Atomic tests executed:** Windows Credential Editor, ProcDump LSASS dump, comsvcs.dll dump, direct syscalls + API unhooking, Mimikatz, pypykatz
- **id:** `cc9b25d6-efc9-11eb-926b-550bf0943fbb` (used as the `host` field in Splunk)

### 2.2 Map techniques to log sources

| MITRE sub-technique | Expected log source | What you'd see |
|---------------------|---------------------|----------------|
| T1003.001 — LSASS Memory | Sysmon Event ID 10 | `lsass.exe` accessed by `procdump.exe`, `cmd.exe`, `rundll32.exe` |
| T1003.001 — LSASS Memory | Windows Security 4688 | `procdump.exe`, `rundll32.exe comsvcs.dll,Minidump` spawned |
| T1003.001 — LSASS Memory | Windows Security 4656/4663 | Handle opened to `lsass.exe` process |
| T1003.001 — Mimikatz | PowerShell / Sysmon | `pypykatz`, `mimikatz` command lines |
| T1003.001 — ProcDump | Sysmon Event ID 1 | `procdump.exe -ma lsass.exe ...` |

**Validation:** Run this search to see if your data matches the expected pattern:

```splunk
index=attack_data sourcetype=XmlWinEventLog
| search ProcessName="*lsass*" OR ProcessCommandLine="*lsass*" OR ParentProcessName="*lsass*"
| table _time, host, source, EventCode, ProcessName, ProcessCommandLine, ParentProcessName, User
| sort -_time
```

---

## Phase 3: Run Splunk detections (ESCU)

**Objective:** Run Splunk's own detection content (ESCU) against your replayed data and interpret the hits — just like a SOC analyst triaging SIEM alerts.

### 3.1 Run detections filtered to T1003

```bash
cd /home/arash/Desktop/VibeCodes/splunk/attack_data
source venv/bin/activate

python bin/run_escu_detections.py \
  --time-range "-24h,now" \
  --max-results 1000 \
  --filter-mitre T1003 \
  --filter-status production \
  --output-report escu_t1003_report.txt \
  --output-json escu_t1003_results.json \
  --verbose
```

### 3.2 Review the report

```bash
cat escu_t1003_report.txt
```

**What to look for:**
- Detections with `result_count > 0` = potential alerts
- Detections with `result_count = 0` = either no malicious activity or detection didn't match this data format
- Note the detection name, MITRE ID, and SPL query for each hit

### 3.3 Inspect detailed results

```bash
python3 -c "
import json
with open('escu_t1003_results.json') as f:
    data = json.load(f)
for r in data:
    print(r.get('detection_name','N/A'), '|', r.get('mitre_attack_id','N/A'), '|', r.get('result_count',0), 'results')
    if r.get('result_count',0) > 0:
        print('  SPL:', r.get('search','N/A')[:200])
        print()
"
```

### 3.4 Re-run a fired detection manually in Splunk Web

Pick one detection that returned results. Copy its SPL from the JSON report into **Search & Reporting** and run:

```splunk
# Example placeholder — replace with actual SPL from escu_t1003_results.json
index=attack_data sourcetype=XmlWinEventLog ProcessName="*procdump*" OR ProcessCommandLine="*lsass*"
| table _time, host, ProcessName, ProcessCommandLine, User, Dest
| sort -_time
```

**Validation:** You have at least one ESCU detection with results, and you can reproduce one hit manually in Splunk Web.

---

## Phase 4: Alert triage & investigation

**Objective:** Practice the analyst workflow — take a detection hit, determine true/false positive, and document findings.

### 4.1 Triage template

For each fired detection, answer:

| Question | How to answer in Splunk |
|----------|------------------------|
| What happened? | Read the event fields (ProcessName, ProcessCommandLine, User, Dest) |
| When did it happen? | `_time` field, sort ascending |
| Who was involved? | `User`, `Dest`, `host` |
| What was the parent process? | `ParentProcessName`, `ParentProcessCommandLine` |
| Is this normal admin activity or malicious? | Compare against known admin tools vs. attack tools (procdump, comsvcs.dll, mimikatz) |
| What was the impact? | Credential material potentially extracted from LSASS |
| What is the confidence? | High if multiple sources correlate (Sysmon + Security + CrowdStrike) |

### 4.2 Build a timeline

```splunk
index=attack_data host="cc9b25d6-efc9-11eb-926b-550bf0943fbb"
| sort _time
| table _time, sourcetype, source, EventCode, ProcessName, ProcessCommandLine, ParentProcessName, User, Dest
| head 200
```

**What to look for:** A cluster of events within minutes involving `lsass.exe`, `procdump.exe`, `rundll32.exe`, or `cmd.exe` — this is the attack timeline.

### 4.3 Process ancestry

```splunk
index=attack_data sourcetype=XmlWinEventLog
| stats values(ProcessName) as processes, values(ParentProcessName) as parents by host
| eval parent_child = mvzip(parents, processes)
| table host, parent_child
```

**What to look for:** Unusual parents — e.g., `cmd.exe` spawning `procdump.exe`, or `rundll32.exe` spawning `comsvcs.dll` (classic LSASS dump pattern).

### 4.4 Document findings

Create a file `/home/arash/Desktop/VibeCodes/splunk/triage_t1003.md` with:

```
# Triage — T1003.001 Credential Dumping
Date: <today>
Alert: <detection name from ESCU>
Source: index=attack_data
MITRE: T1003.001
Events reviewed: <count>
Host: cc9b25d6-efc9-11eb-926b-550bf0943fbb
Timeline summary: <2-3 sentences>
Verdict: True Positive / False Positive
Evidence: <key SPL queries and event counts>
Recommended action: <escalate / close / tune>
```

**Validation:** You have a written triage note with a verdict and evidence.

---

## Phase 5: Threat hunting (hypothesis-driven)

**Objective:** Practice proactive hunting — don't wait for alerts, go look for adversary behavior.

### Hunt 1: LSASS access (process opened lsass.exe)

```splunk
index=attack_data sourcetype=XmlWinEventLog EventCode="10" OR EventCode="1"
| search TargetProcessName="lsass.exe" OR ProcessName="lsass.exe"
| table _time, host, ProcessName, ProcessCommandLine, TargetProcessName, GrantedAccess, User
| sort -_time
```

**What to look for:** `GrantedAccess` values like `0x1010` (PROCESS_VM_READ) or `0x1438` (full access) to `lsass.exe` from non-system processes.

### Hunt 2: Minidump / dump file creation

```splunk
index=attack_data sourcetype=XmlWinEventLog
| search ProcessCommandLine="*procdump*" OR ProcessCommandLine="*comsvcs.dll*" OR ProcessCommandLine="*Minidump*"
| table _time, host, ProcessName, ProcessCommandLine, ParentProcessName, User
| sort -_time
```

**What to look for:** `rundll32.exe comsvcs.dll,Minidump <pid> <dumpfile> full` — a classic LSASS dump one-liner.

### Hunt 3: Credential dumping tools

```splunk
index=attack_data
| search ProcessName="*mimikatz*" OR ProcessName="*procdump*" OR ProcessName="*pypykatz*" OR ProcessCommandLine="*lsass*"
| table _time, host, sourcetype, ProcessName, ProcessCommandLine, User, Dest
| sort -_time
```

**What to look for:** Any known credential-dumping tooling appearing in your environment.

### Hunt 4: Cross-source correlation

```splunk
index=attack_data host="cc9b25d6-efc9-11eb-926b-550bf0943fbb"
| stats count by sourcetype, source, EventCode
| sort -count
```

**What to look for:** Do Sysmon, Windows Security, and CrowdStrike all see the same activity? If only one source sees it, you may have a visibility gap.

**Validation:** You run at least 3 hunts, document what each found (or didn't find), and note which hunt would be most valuable in a real SOC.

---

## Phase 6: Detection engineering (write your own)

**Objective:** Learn to write, test, and tune detections — the core of detection engineering.

### 6.1 Write a custom detection

Based on what you saw in Phase 4, create a SPL detection for LSASS dumping:

```splunk
index=attack_data sourcetype=XmlWinEventLog
| search (ProcessName="procdump.exe" OR ProcessCommandLine="*procdump*" OR ProcessCommandLine="*comsvcs.dll*" OR ProcessCommandLine="*Minidump*")
| stats count as alert_count, values(_time) as times, values(ProcessName) as processes, values(User) as users by host, ParentProcessName
| where alert_count > 0
| table host, ParentProcessName, processes, users, alert_count
```

### 6.2 Test it

Run the above in **Search & Reporting**. If it returns events, your detection works against this dataset.

### 6.3 Tune for false positives

Ask:
- Would `procdump.exe` ever be run by a legitimate admin? Yes.
- How to reduce false positives? Only alert when `procdump.exe` targets `lsass.exe`, or when `comsvcs.dll,Minidump` appears.
- Add exclusions: known admin accounts, known maintenance windows.

### 6.4 Save your detection

Create `/home/arash/Desktop/VibeCodes/splunk/detection_lsass_dump.spl`:

```
# Detection: Credential Dumping via ProcDump / comsvcs.dll
# MITRE: T1003.001
# Data: index=attack_data sourcetype=XmlWinEventLog
# Author: <your name>
# Description: Detects LSASS memory dumping via ProcDump or comsvcs.dll Minidump

index=attack_data sourcetype=XmlWinEventLog
| search (ProcessName="procdump.exe" OR ProcessCommandLine="*procdump*" OR ProcessCommandLine="*comsvcs.dll*" OR ProcessCommandLine="*Minidump*")
| stats count as alert_count by host, ParentProcessName, ProcessName, ProcessCommandLine, User
| table _time, host, ParentProcessName, ProcessName, ProcessCommandLine, User, alert_count
```

**Validation:** You wrote a detection, tested it against replayed data, and documented tuning considerations.

---

## Phase 7: Expand the lab

**Objective:** Practice with more techniques and larger datasets.

### 7.1 Pull another technique

```bash
cd /home/arash/Desktop/VibeCodes/splunk/attack_data
git lfs pull --include="datasets/attack_techniques/T1059/atomic_red_team/"
```

### 7.2 Replay it

```bash
source venv/bin/activate
export SPLUNK_HOST="127.0.0.1"
export SPLUNK_HEC_TOKEN="c1aa30d0-c5a5-43cc-8ee3-329a5253565a"
export SPLUNK_USERNAME="admin"
export SPLUNK_PASSWORD="S0cPractice!2026"
export SPLUNK_PORT="8089"
export SPLUNK_VERIFY_SSL="false"

python bin/replay.py datasets/attack_techniques/T1059/atomic_red_team/
```

### 7.3 Run ESCU against both techniques

```bash
python bin/run_escu_detections.py \
  --time-range "-7d,now" \
  --filter-mitre T1003 T1059 \
  --output-report escu_multi_report.txt \
  --output-json escu_multi_results.json
```

### 7.4 Compare detections

- Which technique generated more alerts?
- Which detections fired for both?
- Which data source was most valuable for each?

---

## Daily drill template (30–60 minutes)

If you want to practice regularly, use this repeatable structure:

| Time | Activity |
|------|----------|
| 0:00–0:10 | Pick a technique folder, `git lfs pull` it, `python bin/replay.py` it |
| 0:10–0:20 | Run `index=attack_data \| stats count by sourcetype` — explore what landed |
| 0:20–0:30 | Read the technique's `.yml` — understand what was simulated |
| 0:30–0:40 | Run ESCU detections filtered to that MITRE ID |
| 0:40–0:50 | Triage the top 2–3 hits using the Phase 4 template |
| 0:50–1:00 | Write a custom detection or run a hunt query from Phase 5 |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `index=attack_data` returns 0 events | Wait 30–60s for Splunk to index HEC events, then re-run |
| ESCU script returns no results | Widen time-range to `-7d,now`; confirm data was replayed into `attack_data` index |
| HEC token errors (code 4) | Re-copy the token from Splunk Web → Settings → Data Inputs → HTTP Event Collector |
| Port 8000 already in use | Change the left side of port mapping in `docker-compose.yml` (e.g., `8001:8000`) |
| `run_escu_detections.py` fails to clone security_content | Ensure network access to GitHub; the script clones `./security_content` automatically |

---

## Where things live on your system

| Path | Purpose |
|------|---------|
| `/home/arash/Desktop/VibeCodes/splunk/docker-compose.yml` | Splunk Docker config |
| `/home/arash/Desktop/VibeCodes/splunk/attack_data/` | Cloned repo + T1003.001 data |
| `/home/arash/Desktop/VibeCodes/splunk/attack_data/venv/` | Python environment |
| `/home/arash/Desktop/VibeCodes/splunk/attack_data/datasets/attack_techniques/T1003.001/atomic_red_team/atomic_red_team.yml` | Scenario description |
| `/home/arash/Desktop/VibeCodes/splunk/SOC_EXERCISE_GUIDE.md` | Lab setup reference |
| `/home/arash/Desktop/VibeCodes/splunk/SOC_PRACTICE_GUIDE.md` | This file |

---

## Success criteria

You've completed this practice guide when you can:

- [ ] Replay an attack dataset into Splunk via HEC
- [ ] Run ESCU detections and interpret the report
- [ ] Build a timeline from raw Windows/Sysmon/CrowdStrike logs
- [ ] Triage an alert and write a verdict with evidence
- [ ] Write and test a custom SPL detection
- [ ] Run 3+ hypothesis-driven hunts against the same data

Start with Phase 1 and work down. When you're ready to add a new technique, return to Phase 7.