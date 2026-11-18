# Scenario Mode — staged implementation plan

**Status:** Phases 0–4 implemented (loader, preflight, checks, progress, UI);
Phase 5 content started with
`scenarios/T1003-001-Credential-dumping-on-a-Windows-host.json`. The scenario
detail offers a one-click **Set up scenario** job using `dataset.repo` and
`dataset.path` from the JSON.
**Companion guide:** `docs/SCENARIO_AUTHORING_AGENT.md` — how an agent turns a
dataset folder plus suggested searches into a scenario JSON.
**Scope:** a new **Scenarios** tab that turns a replayed `attack_data` dataset into a
guided, stage-by-stage incident with questions and search-based validation.
The existing Playbook stays as the free-form query reference.

## Goals

- Teach the analyst workflow, not just individual searches: orient → triage →
  hunt → scope → detection → verdict → debrief.
- Validate understanding against real telemetry, not just multiple-choice.
- Scope every check to the scenario's dataset (`host` = YAML `id`) so other
  replayed techniques cannot leak evidence into the answer.
- Work offline with the current stack (Splunk container + local attack_data).
- Make scenario content cheap to add and review (JSON, no code changes).

## Non-goals (for now)

- Splunk Security Essentials coverage integration.
- Splunk SOAR escalation and playbooks.
- LLM-based grading.
- Auto-generating scenarios from arbitrary dataset folders.

These are deliberately deferred; see Phase 7.

## Design decisions

| Decision | Recommendation | Why |
|---|---|---|
| Progress storage | Server-side JSON (`state/scenarios.json`) | Survives browser changes, lets the server grade |
| Answer/check secrecy | Never send check SPL or correct answers to the browser | Students should not inspect answers in devtools |
| Query help | Hide the authoring `starter_spl`; offer **New search** and **Open Splunk** | The hunt should be the student's own work |
| Grading strictness | Hard checks for searches/evidence; soft review for free text | Free text is ambiguous without an instructor |
| Count-based assertions | Presence/distinct/range, not exact row counts | Replay can duplicate events; checks must be idempotent |
| Scenario data | One curated JSON file per scenario | Reviewable in git; no code changes to add content |
| Host scope | Resolve `dataset.path` → YAML `id` → `host="..."` | Same dataset may be replayed alongside others |
| Tab position | Dashboard · Scenarios · Datasets · Search · Playbook | Scenarios is a guided entry point |

## Proposed file layout

```
soc_lab/
  scenarios/
    T1003-001-Credential-dumping-on-a-Windows-host.json
    T1059-001-PowerShell-execution.json
    persistence-001.json
  state/                       # gitignored, created at runtime
    scenarios.json
  app.py                       # scenario loader, checks, progress API
  ui/app.js, index.html        # Scenarios tab
  docs/SCENARIO_AUTHORING.md   # schema + authoring checklist
```

## Scenario schema (v1)

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
  "briefing": "It is 09:15. ...",
  "stages": [
    {
      "id": "orient",
      "title": "Orient",
      "narrative": "Before touching the alert, confirm what telemetry is available.",
      "question": "Which two log sources are present in this dataset?",
      "answer": {
        "type": "choice",
        "options": ["Sysmon + CrowdStrike", "Security + Firewall", "Only PowerShell"],
        "correct": 0
      },
      "starter_spl": "index=attack_data host=\"...\" | stats count by sourcetype source",
      "hints": ["Start with a count by sourcetype and source."],
      "debrief": "Sysmon provides process/network detail; CrowdStrike adds sensor context."
    },
    {
      "id": "hunt",
      "title": "Find the dump",
      "narrative": "The alert says lsass.exe was accessed. Find the process responsible.",
      "question": "Which process accessed LSASS, and with what access mask?",
      "checks": [
        {
          "type": "search",
          "spl": "index=attack_data host=\"...\" EventCode=10 TargetImage=\"*lsass.exe\" | stats values(SourceImage) as source values(GrantedAccess) as access",
          "expect": {"min_rows": 1, "contains": {"source": "procdump"}}
        },
        {
          "type": "answer",
          "accepted": ["procdump", "procdump.exe", "procdump64.exe"]
        }
      ],
      "starter_spl": "index=attack_data host=\"...\" sourcetype=XmlWinEventLog EventCode=10 | table _time SourceImage TargetImage GrantedAccess User",
      "hints": ["Sysmon event 10 is process access. Look at SourceImage and GrantedAccess."],
      "debrief": "ProcDump opened LSASS with a read/full-access mask — the classic dump pattern."
    }
  ],
  "debrief": "Summary of the incident, what a real SOC would do, and tuning notes."
}
```

`starter_spl` in the example is an authoring reference. The public scenario API
never sends it; the UI gives students a fresh host-scoped search instead.

`dataset.repo` and `dataset.path` are the download inputs. **Set up scenario**
clones `repo` when no checkout exists, runs `git lfs pull --include=datasets/<path>/*`,
replays the folder's YAML into the lab index, waits for the host's events, and
installs the field extraction. File names should be representative, e.g.
`T1003-001-Credential-dumping-on-a-Windows-host.json`; the `id` stays lowercase.

### Check types

| Type | Evaluated by | Pass example |
|---|---|---|
| `search` | Server runs hidden SPL and inspects fields | At least one row with `SourceImage` containing `procdump` |
| `answer` | Normalized string / accepted list / regex | `procdump64.exe` |
| `choice` | Index comparison | Option 0 |
| `evidence` | Student selects rows; server verifies field values | Selected row has `TargetImage=lsass.exe` |
| `spl` | Server runs the student's SPL and checks the result set | Results contain the expected host/user pair |
| `review` | Free text, not auto-failed | Explanation saved for the debrief |

Rules:
- All `search`/`spl` checks run with `earliest=0`, a row limit, and a timeout.
- Use `min_rows`, `max_rows`, `contains`, `regex`, `equals`, `distinct_at_least`.
- Deduplicate or use presence checks; do not assert exact counts.
- A stage passes only when every hard check passes. `review` stages are marked
  "noted", not blocking.

## Stages of work

### Phase 0 — Confirm scope and sample content (0.5 day)

- [ ] Pick three datasets that are already downloaded, field-rich, and reliable:
  - candidate A: `T1003.001/atomic_red_team` (LSASS dumping)
  - candidate B: `T1059.001/...` or another PowerShell dataset
  - candidate C: `T1112/...` or `T1543.003/...` (persistence/service)
- [ ] Verify each dataset's host, event count, and key fields against Splunk.
- [ ] Decide whether progress is per scenario or per scenario + host.
- [ ] Freeze the v1 schema above.

**Exit:** three dataset paths and their expected evidence documented.

### Phase 1 — Scenario loader and schema validation (1 day)

- [ ] Add `scenarios/` and load all `*.json` at startup with a short cache.
- [ ] Validate: unique IDs, required fields, valid `dataset.path`, stage IDs
      unique, check types known, `answer.correct` within options.
- [ ] Expose public summaries without check SPL or correct answers.
- [ ] Add unit tests for valid/invalid fixtures and sanitization.
- [ ] Fail closed: a broken scenario is hidden and logged, not half-served.

**Exit:** `/api/scenarios` and `/api/scenario?id=` return only safe fields;
tests prove checks and answers are not leaked.

### Phase 2 — Preflight and dataset readiness (0.5–1 day)

- [ ] Resolve `dataset.path` through the existing scan.
- [ ] Report: repo ready, files local, dataset replayed (host event count),
      field extraction active, Splunk reachable, required fields present.
- [ ] Return actionable states that reuse existing buttons:
      `clone-repo`, `download`, `replay`, `install-fields`, `start-lab`.
- [ ] Scope all starter SPL to the resolved host.
- [ ] Unit-test resolution with mocked scan/status objects (no Splunk).

**Exit:** a scenario card cannot start until its data is ready; the blocking
reason and next action are shown.

### Phase 3 — Validation engine and progress API (2 days)

- [ ] `POST /api/scenario/check` with `scenario_id`, `stage_id`, answer payload.
- [ ] Server-side execution of `search`/`spl` checks via `splunk_search`.
- [ ] Normalize answers: lowercase, trim, strip paths/quotes where appropriate.
- [ ] Return per-check pass/fail, safe feedback, evidence rows, and the next stage.
- [ ] `GET/POST /api/scenario/progress` with atomic JSON writes
      (`state/scenarios.json`), keyed by scenario ID; record completed stages,
      attempts, hints used, timestamps.
- [ ] `POST /api/scenario/reset`.
- [ ] Add `state/` to `.gitignore`.
- [ ] Tests: validator unit tests with a fake search runner; progress write/resume;
      duplicate-event tolerance; timeout and search-error handling.

**Exit:** one scenario's checks pass/fail correctly via API, progress survives a
server restart, and no hidden SPL appears in responses.

### Phase 4 — Scenarios UI (2–3 days)

- [ ] Add the **Scenarios** tab and nav entry.
- [ ] List view: title, summary, technique, difficulty, estimated time,
      progress bar, completed badge.
- [ ] Runner: stage rail, narrative, question widget, hints, fresh host-scoped
      search and Splunk Web buttons, submit, check feedback, next stage, final debrief.
- [ ] Reuse the existing results table renderer for evidence; add a compact
      mode rather than duplicating table code.
- [ ] Preflight screen with one **Set up scenario** job (clone, download,
      replay, wait, install fields) instead of per-step buttons.
- [ ] **Load scenario** button: validates an uploaded JSON file, writes it to
      `scenarios/`, then refreshes and opens it.
- [ ] Reset button with confirmation.
- [ ] Accessibility: labels, keyboard submit, focus movement on stage change.
- [ ] Headless-browser smoke test for one full scenario path.

**Exit:** a new user can go from scenario card → preflight → stages → debrief
without touching Datasets or Search.

### Phase 5 — Author three scenarios (2–4 days, content-heavy)

- [ ] LSASS credential dumping (`T1003.001`), 5–7 stages.
- [ ] PowerShell execution/obfuscation (`T1059.001`), 5–7 stages.
- [ ] Persistence via registry or service (`T1112` / `T1543.003`), 5–7 stages.
- [ ] Each scenario: briefing, hints, expected evidence, debrief, tuning notes.
- [ ] Tune checks against actual data, including a duplicate replay.
- [ ] Record required fields and minimum Splunk version assumptions.

**Exit:** each scenario completes in 20–30 minutes, all checks pass on a fresh
progress state, and hints are useful without giving away the answer.

### Phase 6 — Documentation and polish (1 day)

- [ ] `docs/SCENARIO_AUTHORING.md`: schema, check reference, idempotency rules,
      how to test a scenario, review checklist.
- [ ] README section for the Scenarios tab.
- [ ] Update `AGENTS.md` with loader/check/progress invariants.
- [ ] Final test pass: unit suite + browser smoke + manual run.
- [ ] Optionally export a completed-scenario debrief as Markdown.

**Exit:** a contributor can add a scenario without reading `app.py`.

### Phase 7 — Deferred extensions

- [ ] Map stages to Splunk Security Essentials use cases and show coverage.
- [ ] "Escalate to SOAR" stage (real SOAR or a local case mock).
- [ ] Scoring: hints/attempts, time, quality of evidence.
- [ ] Scenario packs by difficulty/role (Tier 1 triage, detection engineer).
- [ ] Scenario builder that scaffolds stages from a dataset YAML and recipes.
- [ ] Multi-dataset campaigns (initial access → credential access → exfil).

## API additions

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/scenarios` | Safe list with progress summary |
| GET | `/api/scenario?id=` | Safe scenario detail, no checks/answers |
| POST | `/api/scenario/check` | Grade one stage |
| GET | `/api/scenario/progress?id=` | Load progress |
| POST | `/api/scenario/progress` | Save/reset progress (or dedicated reset) |

## Acceptance criteria

- [ ] No correct answers or hidden check SPL are present in browser responses.
- [ ] Every check is host-scoped and duplicate-replay tolerant.
- [ ] Starting a scenario without data shows the exact remediation action.
- [ ] Progress survives a server restart.
- [ ] A broken scenario cannot crash the app or block other scenarios.
- [ ] All unit tests pass; one headless-browser end-to-end run passes.
- [ ] Three scenarios are complete, reviewed, and documented.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Exact counts break after a duplicate replay | Presence/range/distinct assertions |
| Dataset fields differ from expectations | Per-scenario `required_fields` and preflight warning |
| Free-text grading is subjective | Prefer search/evidence checks; soft-review explanations |
| Hidden checks leak through the API | Public serializers whitelist fields; tests assert absence |
| Scenario SPL is expensive | Row limits, timeouts, `stats`-first checks |
| Content becomes stale as attack_data changes | Pin dataset paths; validate checks in CI-style test script |
| Scope creeps into SSE/SOAR | Keep them in Phase 7 |

## Rough effort

| Phase | Effort |
|---|---|
| 0 scope | 0.5 day |
| 1 loader | 1 day |
| 2 preflight | 0.5–1 day |
| 3 validation/progress | 2 days |
| 4 UI | 2–3 days |
| 5 three scenarios | 2–4 days |
| 6 docs/polish | 1 day |
| **Total** | **~9–13 dev days** |

## Open questions

1. Progress keyed by scenario only, or scenario + replayed host? *Recommend
   scenario + host, so replaying a different variant starts clean.*
2. Should a failed stage reveal the expected answer immediately, or only after
   two attempts? *Recommend show the debrief after a pass; offer a "reveal"
   action that marks the stage as completed-with-help.*
3. Should free-text verdicts block completion? *Recommend no; require a
   minimum length and save it for the debrief.*
4. Do we want a scoring model from day one? *Recommend no; completion and
   attempts first, score later.*
