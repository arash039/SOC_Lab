# Scenario generation agent — one-name brief

**Audience:** an AI agent with a shell, this repository, the `attack_data` checkout,
and the local SOC Lab running at `http://127.0.0.1:8765`.
**Input:** one selector, for example `T1001 · snapattack` (technique · dataset
folder). Nothing else.
**Output:** one working scenario JSON under `scenarios/`, loaded, verified against
the replayed data, with test progress reset, and the replay/download artifacts
this task created removed again (§7).
**Companion reference:** `docs/SCENARIO_AUTHORING_AGENT.md` (rationale and deeper
schema notes). This file is the operating procedure; if the two disagree, follow
the validator in `app.py`, which is the source of truth.

You are authorized to: read the repository, clone `attack_data` if missing,
download one dataset folder, start Splunk, replay the dataset, install the
Windows field extraction, run SPL, create the scenario file, load it, test it
through the API, reset the test progress, and delete **only** the replayed events
and downloaded dataset files this task created, through the app's endpoints.
You are **not** authorized to: delete pre-existing data, other datasets or hosts,
scenarios, the `attack_data` checkout, or Docker volumes; edit `attack_data/` by
hand; modify `app.py`; commit or push; expose the server beyond `127.0.0.1`; ask
the user to copy-paste evidence.

Work autonomously. Ask a question only when the selector matches more than one
equally good folder, or the evidence cannot support any check (see §9).

---

## 0. Input contract

Accept any of these forms:

```
T1001 · snapattack
T1001 | snapattack
T1001/snapattack
T1001 snapattack
```

Parsing rules:

- The technique is the first token: `T` + 4 digits, optionally `.<3 digits>`
  (e.g. `T1001`, `T1003.001`). Case-insensitive.
- The provider/folder is everything after `·`, `|`, `/`, or the first space.
- Normalize for matching only: lowercase, and treat `-`, `_`, `.`, and spaces as
  equivalent. Never rename a real folder.

The selector never contains a path. Resolve it in §1.

---

## 1. Resolve the selector to a dataset folder

`dataset.path` is always relative to `attack_data/datasets/` and stored with
forward slashes.

Search in this order and stop at the first unique match:

1. `datasets/attack_techniques/<TECHNIQUE>/<PROVIDER>` — exact or case-insensitive.
2. `datasets/attack_techniques/<PARENT>/<PROVIDER>` when a sub-technique was
   given (`T1003.001` → also try `T1003`), and the reverse when only a parent was
   given.
3. `datasets/attack_techniques/<TECHNIQUE>/*/` — choose the child whose name
   matches the provider by exact normalized form, then by substring.
4. Fallback: scan every `datasets/**/*.yml` / `*.yaml`, keep those whose
   `mitre_technique` contains the technique, and match the provider against the
   YAML's parent folder name.

Tie-break, in order: (a) the YAML `mitre_technique` matches the requested
technique exactly; (b) the folder has local, non-pointer data files; (c) the
shorter path; (d) alphabetical. Record the chosen path and the reason in the
final report. If two candidates are still equal, show the candidates and stop;
do not guess.

Example (verified in this checkout):

```
T1001 · snapattack
→ datasets/attack_techniques/T1001/snapattack
→ YAML: snapattack.yml, id 359d5738-ce1c-40f4-8360-d544dab6db59,
  mitre_technique [T1001], environment attack_range,
  one XmlWinEventLog:Security source
```

Read **every** YAML in the folder. Extract:

| YAML field | Use |
|---|---|
| `id` | Splunk `host` for every search; never paste the literal into scenario SPL |
| `mitre_technique` | `dataset.techniques` |
| `description` | Source for the briefing, rewritten in your own words |
| `environment` | Debrief context |
| `datasets[]` / `sourcetypes` | Expected files and sourcetypes; verify against the replay |

If the YAML has no `id`, stop: the lab cannot scope the host (§9).

If the YAML declares several hosts or techniques, the scenario still covers one
incident on the YAML `id` host; use the primary technique for the title.

---

## 2. Bring the lab and the data up

Set `BASE=http://127.0.0.1:8765`. If the app is not running, start it from the
repository root with an existing venv, for example:

```bash
.venv/bin/python app.py --no-browser
```

Use `../attack_data/venv/bin/python` only if the project venv does not exist.
Never install packages into the system interpreter.

### 2.1 Preflight loop

```bash
curl -s "$BASE/api/status"
curl -s --get --data-urlencode "path=$FOLDER" "$BASE/api/dataset"
```

Follow the returned state. Act, then poll `/api/jobs` until the job is `done` or
`failed`; never assume a 202 means finished.

**Record the starting state before changing anything.** Cleanup in §7 depends on
it:

- Did `attack_data` already exist before you cloned it?
- Were the dataset's files already local (`state: ready`) before you downloaded?
- Did the host already have events before you replayed?

Only artifacts this task created are yours to remove. Never clean up state the
user already had.

| State | Action |
|---|---|
| `repo.path` missing / `attack_data` absent | `POST /api/repo/clone {}` |
| `/api/dataset` returns 404 | Re-check the path in §1; the checkout may be stale. Refresh the dashboard scan (`GET /api/datasets?refresh=1`). |
| `state` is `missing` or `partial`, or files show `pointer: true` | `POST /api/download {"path": FOLDER}` |
| Splunk `reachable: false` | `POST /api/lab/start {}` (skip if Docker is already starting) |
| Host has no events | `POST /api/replay {"path": FOLDER}` |
| Host already has events for this path | **Do not replay.** Duplicates are expected but unnecessary while authoring. |
| `fields.installed` false, or Windows fields missing | `POST /api/install-fields {}` |

Job payloads:

```bash
curl -s -X POST "$BASE/api/download" -H 'Content-Type: application/json' \
  -d '{"path":"attack_techniques/T1001/snapattack"}'
curl -s -X POST "$BASE/api/replay" -H 'Content-Type: application/json' \
  -d '{"path":"attack_techniques/T1001/snapattack"}'
curl -s "$BASE/api/jobs"
```

A small `.log` that starts with `version https://git-lfs` is a Git LFS pointer,
not data. Download it through the app; the download job restores tracked files
and runs `git lfs pull` for `datasets/<FOLDER>/*`.

### 2.2 Confirm the replay

The host must have events before any scenario work. Check `/api/status`:

```json
{"loaded":[{"path":"attack_techniques/T1001/snapattack",
            "host":"359d5738-...","count":123}]}
```

Record the host UUID and the path exactly. If indexing lags, re-query for up to
two minutes. If the count stays zero, read the replay job log; fix the cause
(field extraction is not needed to index, HEC/index errors are) instead of
building a scenario around empty data.

`POST /api/scenario/setup` exists and does clone → download → replay (skipped if
the host already has events) → wait → install fields for a saved scenario. While
authoring, the explicit steps above are easier to debug; either is acceptable.

---

## 3. Profile the data and build an evidence map

Run every probe with `range: "all"`, `limit: 200`, and the real host. Do not use
the dashboard's default 24h range; replayed data may look old.

```bash
curl -s -X POST "$BASE/api/search" -H 'Content-Type: application/json' \
  -d '{"q":"index=attack_data host=\"<HOST>\" | stats count by sourcetype source","range":"all","limit":200}'
```

Replace `<HOST>` with the recorded UUID in these probes only. Scenario SPL keeps
the literal `host="<HOST>"` placeholder.

### 3.1 Required probes

1. **Inventory** — `stats count by sourcetype source`.
2. **Event mix** — `sourcetype=XmlWinEventLog | stats count by EventCode`.
3. **Embedded events** — some XML packs several `<Event>` blocks per Splunk
   event; if counts look too low:
   ```spl
   index=attack_data host="<HOST>"
   | rex max_match=0 "<EventID>(?<EventID>\d+)</EventID>"
   | mvexpand EventID
   | stats count by EventID
   ```
   Use `rex` on `_raw` for those fields; extraction only sees the first block.
4. **Field coverage** — count `EventCode`, `Image`, `NewProcessName`,
   `CommandLine`, `User`, `SubjectUserName`, plus technique-relevant fields.
   Zero counts mean the extraction is off or the schema is different.
5. **Timeline** — process creation (`EventCode=1 OR 4688`), coalescing
   `Image`/`NewProcessName` and `ParentImage`/`ParentProcessName`.
6. **Parent → child pairs** — `stats count by Parent Process`.
7. **Technique-specific evidence** — use `recipes.json` as a menu, but re-run
   every query with the scenario host and time range `all`. Add the ATT&CK
   technique's behavior, not just the recipe list.
8. **Raw samples** — 2–3 representative events per sourcetype, trimmed. Read the
   exact field names and values you intend to grade.

Prefer value-level facts over counts: `SourceImage`, `CommandLine`, `TargetObject`,
`ServiceName`, `DestinationIp`, account and host values. These survive duplicate
replays; counts do not.

### 3.2 Evidence map (write this before authoring)

```
Dataset: attack_techniques/T1001/snapattack
Repo: https://github.com/splunk/attack_data.git
Host: <recorded UUID>
Technique: T1001
Sources: XmlWinEventLog:Security (N events)
Observed:
  - EventCode 4688: <process> <command line> by <account>
  - <other stable field=value pairs>
Unknown / not observed: <list>
Candidate checks:
  - orient: sources contain ...
  - hunt: CommandLine contains ...
```

Rules: only observed values become answers, choices, or `expect` values.
"Inferred" is allowed in the narrative; it is never allowed in a check.

---

## 4. Design the scenario

Aim for 5–7 stages and 20–30 minutes:

| Stage | Student task | Typical gate |
|---|---|---|
| Orient | Which sources/event types are present? | `choice` or `search` |
| Triage | Which process/user/account is involved? | `search` + stage `answer` |
| Hunt | Find the command, access mask, key, path | `search` |
| Scope | Other hosts, accounts, or techniques? | `search` + `answer` |
| Detection | Pick or write a detection | `choice`, optional `spl` |
| Verdict | TP/FP + reasoning + action | `choice` + `review` |

Mix question types. Do not make every stage a search, and do not make every
answer a filename lookup.

For the selected technique, use the observed event classes to choose the story
(e.g. T1001 is data obfuscation: encoded/encrypted command lines in process
creation, not LSASS). If the dataset does not actually show the technique's
behavior, stop and report it rather than inventing a story.

---

## 5. Write the JSON

Create `scenarios/<TECHNIQUE>-<slug>.json`, for example
`T1001-snapattack-data-obfuscation.json`. The filename is for humans; the `id`
must be unique lowercase `[a-z0-9][a-z0-9-]{2,80}` and is what progress keys on.
Check `scenarios/*.json` first: never reuse an `id`, and never overwrite an
existing file.

Template (all required fields shown):

```json
{
  "schema_version": 1,
  "id": "t1001-snapattack-data-obfuscation",
  "title": "Encoded commands on a Windows host",
  "summary": "An alert fired for obfuscated command execution. Reconstruct the activity and decide whether to escalate.",
  "dataset": {
    "repo": "https://github.com/splunk/attack_data.git",
    "path": "attack_techniques/T1001/snapattack",
    "techniques": ["T1001"],
    "required_fields": ["EventCode", "CommandLine", "User"]
  },
  "difficulty": "beginner",
  "estimated_minutes": 25,
  "briefing": "It is 09:15. ...",
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
      "title": "Hunt the command",
      "narrative": "...",
      "question": "...",
      "checks": [
        {"type": "search", "spl": "index=attack_data host=\"<HOST>\" ...",
         "expect": {"min_rows": 1, "contains": {"cmd": "..."}}}
      ],
      "starter_spl": "index=attack_data host=\"<HOST>\" ...",
      "hints": ["..."],
      "debrief": "..."
    }
  ],
  "debrief": "Verdict, evidence, and one tuning note."
}
```

Validator rules (`validate_scenario` in `app.py`):

- `schema_version` must be the integer `1`.
- `title`, `summary`, `briefing`, and every stage's `title`, `narrative`,
  `question`, `debrief` must be non-empty strings.
- `dataset.path` must not start with `/` and must contain no `..` segment.
- `dataset.repo` must be `http(s)://...` or `git@...`; use the canonical
  `https://github.com/splunk/attack_data.git`.
- Every stage needs an `answer` or at least one check. Stage IDs are unique
  lowercase slugs; hints are a list of strings.
- Check types: `search`, `spl`, `review` in `checks`; `answer`, `choice` at the
  stage level. The runner only renders inputs for stage-level `answer`, `spl`,
  and `review`, so never put a graded question inside `checks`.
- `expect` keys: `min_rows`, `max_rows`, `contains`, `equals`, `regex`,
  `distinct_at_least`. Values in `contains`/`equals`/`regex` are field names.
- `choice.correct` is a zero-based index and there must be at least two
  non-empty options.
- Answer matching lowercases, trims quotes, takes the basename after `\` or `/`,
  and drops a trailing `.exe`. `procdump64.exe`, `C:\Tools\procdump.exe`, and
  `procdump` all match `accepted: ["procdump"]`.

Content rules:

- `required_fields` must be populated for this host (preflight proves it). List
  only fields your checks actually use.
- Keep `host="<HOST>"` in every SPL; never hardcode the UUID.
- `starter_spl` is an authoring reference and is never sent to the browser.
- Hints narrow the method; they never state the answer or the check query.
- `narrative`, `question`, `hints`, `title`, and `summary` must not contain
  hidden check SPL, accepted answers, or a correct option verbatim.
- Each stage debrief appears only after that stage passes; the top-level debrief
  appears only after all stages pass.
- The final debrief states the verdict, the evidence, and one tuning note.

---

## 6. Verify before declaring success

### 6.1 Structural validation

```bash
python3 -m json.tool scenarios/<FILE>.json >/dev/null
.venv/bin/python - <<'PY'
import json, sys
sys.path.insert(0, ".")
import app
doc = json.load(open("scenarios/<FILE>.json"))
app.validate_scenario(doc)
print("valid:", doc["id"])
PY
```

Fix every error: the app silently skips an invalid file with a stderr warning.

### 6.2 Run every hidden check against the replay

Save this as `/tmp/opencode/verify_scenario.py` and run it from `soc_lab/` with
the project venv. It runs every `search` check with the resolved host and the
same `expect_holds` function the server uses.

```python
import json, sys, urllib.request
from pathlib import Path

sys.path.insert(0, str(Path.cwd()))
import app

doc = json.loads(Path(sys.argv[1]).read_text())
app.validate_scenario(doc)
host = app.scenario_host(doc)
if not host:
    sys.exit("no host: download and replay the dataset first")

def call(path, body):
    req = urllib.request.Request(
        "http://127.0.0.1:8765" + path,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    return json.load(urllib.request.urlopen(req))

bad = 0
for stage in doc["stages"]:
    for check in stage.get("checks") or []:
        if check["type"] != "search":
            continue
        spl = app.scope_spl(check["spl"], host)
        out = call("/api/search", {"q": spl, "range": "all", "limit": 200})
        rows = out.get("rows") or []
        ok = not out.get("error") and app.expect_holds(rows, check["expect"])
        print(("PASS" if ok else "FAIL"), stage["id"], "rows=%d" % len(rows))
        bad += not ok
sys.exit(1 if bad else 0)
```

Run it twice. A check must pass both times. Then submit the scenario through the
real grader to prove stage-level answers, `spl` checks, and debrief gating work:

```bash
# For each stage, send only the inputs it uses. Use the correct answer from the JSON.
curl -s -X POST "$BASE/api/scenario/check" -H 'Content-Type: application/json' \
  -d '{"scenario_id":"<ID>","stage_id":"<STAGE>","answer":0,"review":"test"}'
```

For a `spl` check, submit a working query such as the check's own SPL and confirm
`passed: true`. Then reset the test progress:

```bash
curl -s -X POST "$BASE/api/scenario/reset" -H 'Content-Type: application/json' \
  -d '{"scenario_id":"<ID>"}'
```

If you deliberately replay the folder a second time to test duplicates, do it
only after the first verification pass, and re-run §6.2 afterward.

### 6.3 Leak check

```bash
curl -s --get --data-urlencode "id=<ID>" "$BASE/api/scenario"
```

The response must contain no `checks`, `starter_spl`, `accepted`, `correct`, or
stage `debrief` before completion. Hints and narratives are public; keep them
clean.

### 6.4 Regression suite

```bash
.venv/bin/python test_app.py
```

It must pass unchanged. Do not edit tests to fit a scenario.

---

## 7. Clean up the artifacts you created

Do this **last**, after §6 verification and after resetting test progress. It is
mandatory unless a safety gate below says otherwise. Delete only what this task
created; never touch pre-existing data.

The app's own endpoints do the work; do not `rm` files or delete Splunk events by
hand.

### 7.1 Delete the replayed events

Only when this task replayed the dataset (the host had no events beforehand):

```bash
curl -s -X POST "$BASE/api/dataset/delete-replay" \
  -H 'Content-Type: application/json' \
  -d '{"path":"<FOLDER>"}'
```

This runs `| delete` for the YAML host and requires the `can_delete` role, which
`delete_events()` grants on first use. Poll `/api/jobs` until `done`. Deleted
events leave searches immediately; disk is reclaimed later by Splunk.

**Skip** if the host already had events before this task. Deleting them would
destroy data the user replayed earlier.

### 7.2 Delete the downloaded files

Only when this task downloaded the dataset (the files were missing, partial, or
Git LFS pointers beforehand):

```bash
curl -s -X POST "$BASE/api/dataset/delete-download" \
  -H 'Content-Type: application/json' \
  -d '{"path":"<FOLDER>"}'
```

This removes only the folder's local log files and keeps the YAML metadata.
`Download` restores them later (tracked files from `HEAD`, then `git lfs pull`),
so the cleanup is reversible.

**Skip** if the files were already local before this task; they are the user's.

### 7.3 Leave shared state alone

- Do **not** remove the `attack_data` checkout, even if you cloned it. It is the
  app's shared checkout and may hold other datasets; removing it is a dashboard
  danger-zone action, not part of authoring. Say in the report that you left it.
- Do not delete the scenario file, other scenarios, other hosts' events, Docker
  volumes, or `state/scenarios.json` beyond the progress reset in §6.2.
- Do not re-download or re-replay after cleanup; the scenario's **Set up
  scenario** does that on demand when the user opens it.

After cleanup, confirm the intent: `/api/dataset?path=<FOLDER>` shows the files
missing/pointer and `/api/status` no longer lists the host (or shows zero
events). The scenario JSON stays valid; preflight is expected to be red until
the user runs **Set up scenario**, which is the point of the cleanup.

---

## 8. Final report

End with exactly this information, no filler:

```
Scenario: scenarios/<FILE>.json
ID: <id>
Dataset: <dataset.path>
Host: <UUID>
Stages: <n> (<ids>)
Evidence: <one line per stage: the value that check asserts>
Verification:
  - schema: pass
  - hidden search checks, run 1: <n>/<n>
  - hidden search checks, run 2: <n>/<n>
  - stage grading via /api/scenario/check: <n>/<n>
  - leak check: pass
  - test_app.py: pass
  - progress reset: yes
Cleanup:
  - replayed events: deleted | skipped (<reason: pre-existing>)
  - downloaded files: deleted | skipped (<reason: pre-existing>)
  - attack_data checkout: left in place (shared)
Notes: <dataset limitations, skipped checks, anything the user must know>
```

Do not paste the whole JSON into the reply. Do not claim checks were run when
they were only designed.

---

## 9. Stop conditions

Stop and report precisely what is missing instead of writing a misleading
scenario when:

- the selector matches more than one folder and the §1 tie-breaks do not decide;
- the folder has no YAML, or the YAML has no `id`;
- the dataset never becomes available (LFS file absent from the repository) or
  the host never receives events;
- field extraction cannot be installed and the scenario depends on Windows
  fields;
- the data shows none of the technique's behavior, or only single events;
- every defensible check would assert an exact count, a timestamp, or a volatile
  value;
- the scenario would need a second host, a second dataset, or a second incident;
- a required value cannot be made idempotent under duplicate replays.

Format: `Not suitable: <reason>. Missing: <exact item>.` Lack of data is a valid
outcome; an invented scenario is not.

---

## Appendix A — Worked resolution: `T1001 · snapattack`

```
Selector:      T1001 · snapattack
Folder:        datasets/attack_techniques/T1001/snapattack
YAML:          snapattack.yml
Host:          359d5738-ce1c-40f4-8360-d544dab6db59
Technique:     T1001
Environment:   attack_range
Source:        XmlWinEventLog:Security
Files:         snapattack.log (declared)
```

This checkout's `snapattack.log` is currently a Git LFS pointer, so the first
action is `POST /api/download`, then replay. T1001 is data obfuscation, so the
profile should look for encoded or obfuscated command lines in Security process
creation, not for credential access. Author only from what the replay shows; if
the log contains nothing that supports the technique, use §9.

---

## Appendix B — Files this task may touch

| Path | Change |
|---|---|
| `scenarios/<new-file>.json` | Create exactly one new scenario |
| `state/scenarios.json` | Written by test grading; reset it before handoff |
| `attack_data/datasets/<folder>/` | Read; the app may download LFS files here, then remove them again in §7 if this task added them |
| Splunk index `attack_data` | This task's replay creates events for the YAML host; delete them again in §7 if this task added them |
| `ui/`, `app.py`, `recipes.json`, tests | Never modify for a scenario task |

Never delete a file or event you did not create. Never commit.
