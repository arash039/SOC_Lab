# Agent guide — authoring a scenario from a dataset folder

**Audience:** an AI coding agent working in this repository.
**Input:** one dataset folder under `attack_data/datasets/`, plus optional
suggested SPL from the user.
**Output:** one scenario JSON file under `soc_lab/scenarios/` that conforms to
`docs/SCENARIOS_PLAN.md`.
**Status:** scenario mode is implemented. This guide is still the authoring
procedure; run the JSON through a real replay before committing it.

Read `docs/SCENARIOS_PLAN.md` first. It defines the schema, check types, and
non-goals. This guide is the operational procedure.

---

## 0. Ground rules

- Work only with local data and the local Splunk at `https://127.0.0.1:8089`.
- Never edit, move, or delete files inside `attack_data/`.
- Never commit `attack_data/`, `state/`, downloaded logs, or credentials.
- Every scenario must be based on evidence you actually retrieved from the
  replayed data. Do not invent fields, event codes, commands, or hosts.
- If a query returns zero rows, fix the query, time range, host, or field names
  before writing a stage. Never “fix” it by inventing expected values.
- Prefer the app API over raw REST while it is running: it normalizes Splunk's
  `fields` response and handles time ranges.

Useful endpoints (server started with `.venv/bin/python app.py`):

```bash
BASE=http://127.0.0.1:8765
curl -s "$BASE/api/status"
curl -s "$BASE/api/dataset?path=attack_techniques/T1003.001/atomic_red_team"
curl -s -X POST "$BASE/api/search" -H 'Content-Type: application/json' \
  -d '{"q":"index=attack_data | stats count by sourcetype","range":"all","limit":20}'
```

---

## 1. Choose and inspect the folder

Input is a path relative to `attack_data/datasets`, for example:

```
attack_techniques/T1003.001/atomic_red_team
```

Check what the folder actually contains:

```bash
FOLDER=attack_techniques/T1003.001/atomic_red_team
ls -la "attack_data/datasets/$FOLDER"
```

Read every YAML in the folder. Determine:

| Field | Use |
|---|---|
| `id` | Splunk `host` for all scoped searches |
| `mitre_technique` | Scenario technique(s); required for the UI card |
| `description` | Candidate briefing text; rewrite it, do not dump it verbatim |
| `environment` | Context for the debrief |
| `datasets` / `dataset` | Which files and sourcetypes are expected |
| `sourcetypes` | Legacy-format hint; verify against actual sourcetypes |

Good scenario candidates:

- the folder has at least one `.log`, `.json`, or `.txt` file that is a real
  file, not a Git LFS pointer;
- the YAML declares an `id` and the data contains behaviors worth investigating;
- the telemetry has multiple event types or sources to correlate;
- the data is Windows XML (`sourcetype=XmlWinEventLog`) until additional field
  extractors exist, because the lab's field extraction is Windows-focused.

Avoid folders with no local data, no `id`, a single boring event, or fields the
lab does not extract.

---

## 2. Make the data ready

Check readiness through the app:

```bash
curl -s "$BASE/api/dataset?path=$FOLDER" | python3 -m json.tool
```

Look at `state`, `ready_files`, `file_count`, and `hosts`.

- `missing` or `partial` → download the folder:
  ```bash
  curl -s -X POST "$BASE/api/download" -H 'Content-Type: application/json' \
    -d "{\"path\":\"$FOLDER\"}"
  ```
- `ready` but never replayed → replay it:
  ```bash
  curl -s -X POST "$BASE/api/replay" -H 'Content-Type: application/json' \
    -d "{\"path\":\"$FOLDER\"}"
  ```
- Splunk offline → start it from the dashboard or `POST /api/lab/start`.
- Windows fields missing → `POST /api/install-fields`.

Poll the job log until the job is `done` or `failed`:

```bash
curl -s "$BASE/api/jobs" | python3 -m json.tool
```

Then confirm the host has events:

```bash
curl -s "$BASE/api/status" | python3 -c '
import json,sys
s=json.load(sys.stdin)
for item in s["loaded"]:
    if item["path"] == "'"$FOLDER"'":
        print(item)
'
```

Record the host UUID. Every scenario query must include
`host="<that-id>"`.

> Replaying the same folder twice duplicates events. That is normal in this lab
> and is exactly why checks must not assert exact event counts.

---

## 3. Profile the telemetry

Run these with `"range":"all"` and a small limit. Save the outputs; they are the
evidence base for the scenario.

### 3.1 Inventory

```spl
index=attack_data host="<HOST>"
| stats count min(_time) as first max(_time) as last by sourcetype source
| sort -count
```

### 3.2 Event mix (Windows)

```spl
index=attack_data host="<HOST>" sourcetype=XmlWinEventLog
| stats count by EventCode
| sort -count
```

Interpretation: 1 = process creation, 3 = network, 7 = image load,
10 = process access, 11 = file create, 13 = registry set, 4688 = Security
process creation.

### 3.3 Field coverage

```spl
index=attack_data host="<HOST>" sourcetype=XmlWinEventLog
| stats count as events count(EventCode) as eventcode count(Image) as image
        count(NewProcessName) as newproc count(CommandLine) as cmd
        count(User) as user count(SubjectUserName) as subjuser
```

If key fields are zero, the field extraction is not active or this dataset uses
a different schema. Do not build field-based checks until this is fixed.

### 3.4 Normalized process timeline

```spl
index=attack_data host="<HOST>" sourcetype=XmlWinEventLog (EventCode=1 OR EventCode=4688)
| eval Process=coalesce(Image, NewProcessName),
       Parent=coalesce(ParentImage, ParentProcessName),
       Account=coalesce(User, SubjectUserName)
| table _time EventCode Process Parent CommandLine Account
| sort _time
| head 200
```

### 3.5 Parent → child pairs

```spl
index=attack_data host="<HOST>" sourcetype=XmlWinEventLog (EventCode=1 OR EventCode=4688)
| eval Process=coalesce(Image, NewProcessName),
       Parent=coalesce(ParentImage, ParentProcessName)
| stats count by Parent Process
| sort -count
```

### 3.6 Technique-specific evidence

Use the playbook in `soc_lab/recipes.json` as a menu, but re-test every query
with the scenario host. Examples:

```spl
-- LSASS access
index=attack_data host="<HOST>" sourcetype=XmlWinEventLog EventCode=10
| search TargetImage="*lsass.exe"
| stats values(SourceImage) as source values(GrantedAccess) as access by User
```

```spl
-- dumping command lines
index=attack_data host="<HOST>"
| search CommandLine="*procdump*" OR CommandLine="*comsvcs*" OR CommandLine="*minidump*"
| table _time CommandLine User
```

```spl
-- PowerShell evidence
index=attack_data host="<HOST>"
| search Image="*powershell*" OR NewProcessName="*powershell*" OR CommandLine="*powershell*"
| table _time CommandLine ParentImage User
```

```spl
-- registry persistence
index=attack_data host="<HOST>" sourcetype=XmlWinEventLog EventCode=13
| stats count values(TargetObject) as keys by Image User
```

```spl
-- service creation
index=attack_data host="<HOST>" sourcetype=XmlWinEventLog EventCode=7045
| table _time ServiceName Image ServiceFileName User
```

### 3.7 Evidence extraction for stage design

For each candidate stage, reduce the evidence to stable values:

```spl
index=attack_data host="<HOST>" sourcetype=XmlWinEventLog EventCode=10
| search TargetImage="*lsass.exe"
| stats values(SourceImage) as sources values(GrantedAccess) as access
        values(User) as users dc(SourceImage) as distinct_sources
```

Use this to decide what is stable (`procdump` in `SourceImage`, an account name)
versus what is volatile (`_time`, event counts, IPs that may repeat).

---

## 4. Reconstruct the story

Write a short private evidence map before authoring:

```
Dataset: attack_techniques/T1003.001/atomic_red_team
Host: cc9b25d6-efc9-11eb-926b-550bf0943fbb
Technique: T1003.001
Observed:
  - Sysmon 10: procdump.exe -> lsass.exe, GrantedAccess 0x1010/0x1438, user Administrator
  - Sysmon 1: procdump.exe -mm lsass.exe C:\Windows\Temp\lsass_dump.dmp
  - 4688: NewProcessName ...procdump64.exe, ParentProcessName ...procdump.exe
  - CrowdStrike sensor events: 15
Unknown / not observed: lateral movement, exfiltration
```

Rules:

- Separate **observed** from **inferred**. Questions must be answerable from
  observed data.
- Do not mention hosts, users, or commands that do not appear in results.
- Note negative findings; they are valid stage questions (“was any other host
  involved?”).
- Keep the scenario to one incident and one host unless the dataset proves a
  wider scope.

---

## 5. Design the stage arc

Target 5–7 stages, 20–30 minutes total. A reliable pattern:

| Stage | Student task | Check type |
|---|---|---|
| Briefing | Read the alert; no question | none / start |
| Orient | Inventory sources and event mix | choice or search |
| Triage | Identify process, user, time, parent | search + answer |
| Hunt | Find the malicious command line or access mask | search |
| Scope | Decide whether other hosts/accounts appear | search |
| Detection | Select or write a detection that fires | spl or choice |
| Verdict | TP/FP, evidence, recommended action | choice + review |
| Debrief | Read the explanation; no gating | none |

For each stage decide:

- the **question**, phrased as an analyst would ask it;
- the **starter SPL** (an authoring reference, not shown to students — the UI
  gives them a fresh host-scoped search and Splunk Web);
- the **hidden check SPL** (never sent to the browser);
- the **expected stable evidence**;
- one or two **hints** that narrow the method without naming the answer;
- the **debrief** shown after passing.

Do not make every stage a search. Mix in a multiple-choice decision, an
evidence-selection question, and one short written verdict. Students should
reason, not just paste.

If the user supplied **suggested searches**:

1. Normalize them: add `index=attack_data host="<HOST>"`, fix field names, set a
   sensible `stats`/`table` tail.
2. Run each one and keep only queries that return evidence.
3. Classify each as either a **starter** (authoring reference) or a **check** (hidden).
4. Never put a check query in `starter_spl` or a hint.
5. If the suggested search reveals the answer too directly, use it as the
   debrief or detection stage instead.

---

## 6. Write checks that survive duplicate replays

Checks must be **idempotent**. Duplicate events are expected.

Prefer:

- `min_rows: 1` with `contains` or `regex` on a stable field;
- `distinct_at_least` for cardinality;
- a `stats`/`dedup` tail before returning rows;
- field patterns (`*procdump*`) over exact full paths when paths vary.

Avoid:

- `max_rows` or exact counts of events;
- exact `_time` values;
- exact `GrantedAccess` if the dataset shows multiple values — use membership in
  a set or `contains` on a stable substring;
- checks that only pass once (a second replay must still pass);
- queries without `host="<HOST>"`;
- checks that rely on event ordering.

Check semantics from the plan:

```json
{"type": "search", "spl": "...", "expect": {"min_rows": 1, "contains": {"sources": "procdump"}}}
```

Before writing the file, run the check SPL twice and compare. If you can, replay
the same folder once more and run it a third time. It must still pass.

---

## 7. Write the scenario JSON

Create `soc_lab/scenarios/<technique>-<slug>.json`, named for the case, e.g.
`T1003-001-Credential-dumping-on-a-Windows-host.json`. Follow
`docs/SCENARIOS_PLAN.md` exactly. The `id` is a lowercase slug; the file name is
for humans. Template:

```json
{
  "schema_version": 1,
  "id": "t1003-001-credential-dumping-on-a-windows-host",
  "title": "Credential dumping on a domain controller",
  "summary": "An alert fired for LSASS access. Reconstruct the attack and decide whether to escalate.",
  "dataset": {
    "repo": "https://github.com/splunk/attack_data.git",
    "path": "attack_techniques/T1003.001/atomic_red_team",
    "techniques": ["T1003.001"],
    "required_fields": ["EventCode", "SourceImage", "TargetImage", "CommandLine"]
  },
  "difficulty": "beginner",
  "estimated_minutes": 25,
  "briefing": "...",
  "stages": [
    {
      "id": "orient",
      "title": "Orient",
      "narrative": "...",
      "question": "...",
      "answer": {"type": "choice", "options": ["...", "...", "..."], "correct": 0},
      "starter_spl": "index=attack_data host=\"<HOST>\" ...",
      "hints": ["..."],
      "debrief": "..."
    },
    {
      "id": "hunt",
      "title": "Find the dump",
      "narrative": "...",
      "question": "...",
      "checks": [
        {"type": "search", "spl": "index=attack_data host=\"<HOST>\" ...", "expect": {"min_rows": 1, "contains": {"sources": "procdump"}}},
        {"type": "answer", "accepted": ["procdump", "procdump.exe", "procdump64.exe"]}
      ],
      "starter_spl": "index=attack_data host=\"<HOST>\" ...",
      "hints": ["..."],
      "debrief": "..."
    }
  ],
  "debrief": "..."
}
```

Authoring requirements:

- Keep the literal `host="<HOST>"` in every query; the app substitutes the
  dataset YAML `id` when it serves or runs the scenario.
- Use relative dataset paths; never absolute paths or `../`.
- Include `required_fields` so preflight can warn about missing extraction.
- `starter_spl` is optional and never sent to the browser; keep it as a
  maintainer reference or omit it.
- Keep prompts answerable from the data; hints must not contain the answer.
- Stage IDs are unique, lowercase, URL-safe.
- The final debrief must state the verdict, evidence, and one tuning note.
- Do not include check SPL or correct answers in any client-facing field once the
  loader exists; the loader will strip them.

---

## 8. Test before handoff

Manual test:

1. For each `search`/`spl` check, run the SPL through `POST /api/search` with
   `"range":"all"`.
2. Confirm the expected rows and fields are present.
3. Run every check a second time; ensure the same pass result.
4. If practical, replay the same folder again and re-run; ensure it still
   passes.
5. Run each `starter_spl` as an authoring reference; students do not see it.
6. Confirm no starter or hint reveals a hidden check's expected value.
7. Validate the JSON:

```bash
python3 -m json.tool soc_lab/scenarios/<file>.json >/dev/null
```

8. If a scenario loader exists by then:

```bash
.venv/bin/python test_app.py
```

and call `/api/scenario?id=<id>` to confirm check SPL and answers are absent.

---

## 9. Review checklist

- [ ] Dataset folder exists, files are local, host has events.
- [ ] Host UUID matches the YAML `id`; every query is host-scoped.
- [ ] Technique IDs are correct and present in the YAML.
- [ ] 5–7 stages, 20–30 minutes, mixed question types.
- [ ] Every question is answerable from retrieved evidence.
- [ ] Checks are idempotent, resilient to duplicate events, and time-bounded.
- [ ] Starter SPL (authoring reference) is useful; hints do not give away answers.
- [ ] Required fields are listed and actually present.
- [ ] No absolute paths, no invented values, no external data.
- [ ] Final debrief includes verdict, evidence, and a tuning note.
- [ ] JSON is valid and follows the plan's schema.

---

## 10. Golden-path example (T1003.001)

Folder: `attack_techniques/T1003.001/atomic_red_team`
Host: from `atomic_red_team.yml` (`cc9b25d6-...` in this lab)

Evidence gathered:

- Sysmon 10: `procdump.exe` (or `SourceImage`) accessing `lsass.exe`
- Sysmon 1 / 4688: `procdump.exe -mm lsass.exe C:\Windows\Temp\lsass_dump.dmp`
- User: `ATTACKRANGE\Administrator`
- CrowdStrike events present but secondary

Stage sketch:

1. **Orient** — “Which log sources are present?” Reference query: inventory. Check:
   `stats count by sourcetype` contains `XmlWinEventLog` and
   `crowdstrike:events:sensor`.
2. **Triage** — “What process accessed LSASS and under which account?” Reference:
   Sysmon 10 table. Check: `SourceImage` contains `procdump`, `User` equals the
   observed account.
3. **Hunt** — “Find the command line used to create the dump.” Reference: process
   creation. Check: `CommandLine` contains `procdump` and `lsass`.
4. **Scope** — “Did any other host report this behavior?” Check: distinct hosts
   with the dump pattern; expected one in this dataset.
5. **Detection** — “Which detection would you keep?” Choice between a
   process-name-only rule, a command-line rule, and an unrelated rule. Check the
   choice; optionally verify a candidate SPL fires.
6. **Verdict** — TP/FP choice plus a short free-text justification. Review
   check, not auto-failed.
7. **Debrief** — explain the LSASS access mask, why procdump is suspicious
   here, and how to tune for legitimate admin use.

Do not copy this sketch blindly: verify every value against the current replay,
because the dataset may have been replayed more than once and the environment
may differ.

---

## 11. Stop conditions

Stop and report to the user instead of writing a scenario if:

- the folder has no local data and cannot be downloaded;
- the YAML has no `id` or no usable dataset metadata;
- the parsed events have none of the expected fields and field extraction cannot
  be fixed;
- a technique cannot be reconstructed from the available telemetry;
- the only possible checks are exact counts or volatile values;
- a check cannot be made idempotent.

A short “not suitable for a scenario because …” note is better than a misleading
scenario.
