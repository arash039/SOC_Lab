# SOC Lab

A self-contained local SOC practice lab for `splunk/attack_data`:

```
SOC_Lab/  ──►  app.py  ──►  http://127.0.0.1:8765
   │                         │
   ├─ docker-compose.yml ──► Splunk (8000 / 8088 / 8089)
   └─ attack_data/  (cloned on demand, per-folder LFS pulls)
```

The repo ships the UI, the Splunk Compose setup, and the field-extraction
config. The attack-data repository is **not** committed: the app clones its
metadata with Git LFS smudging disabled and only downloads the dataset folders
you select.

## Quick start

Prerequisites: Docker, `git`, `git-lfs`, Python 3.10+.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
docker compose up -d                 # Splunk Web: http://127.0.0.1:8000
.venv/bin/python app.py              # UI:        http://127.0.0.1:8765
```

In the UI:

1. **Clone attack_data** on the dashboard (metadata only, a few MB).
2. **Install field extraction** when the banner asks (no Splunk restart).
3. Open **Datasets** → pick a technique → **Download** → **Replay**.
4. Open **Playbook** and run the hunts.

Splunk's index and HEC token are created automatically on the first replay if
they do not already exist. Use `--port 8766` if 8765 is taken.

## Docker Compose

`docker-compose.yml` is the canonical lab definition:

- ports `8000` (Web), `8088` (HEC), `8089` (REST)
- named volumes `splunk-etc` / `splunk-var`
- healthcheck and `restart: unless-stopped`
- optional `.env` overrides via `.env.example`

`SPLUNK_HEC_TOKEN` seeds a token on first boot. The app also creates one on
demand, so existing volumes with a different token keep working.

If this repo sits inside a parent project that already has a `docker-compose.yml`
(the development layout), the app uses the parent directory as the Compose
project directory so the existing project name and volumes are preserved.

## attack_data download model

| Action | What happens |
|---|---|
| Clone attack_data | `git clone --depth 1` with `GIT_LFS_SKIP_SMUDGE=1`; no logs downloaded |
| Download dataset | `git lfs pull --include=<folder>/` for that one folder |
| Replay dataset | Sends only the YAML-declared files to HEC |

The full repository is >9 GB. Download only the techniques you are practising.
A checkout at `./attack_data` is preferred; `ATTACK_DATA_DIR` can point at an
existing checkout (for example the parent-folder one used during development).

## Field extraction (required for Windows hunts)

`attack_data` replays raw Windows event XML through HEC. The stock
`XmlWinEventLog` sourcetype does not extract `<Data Name="ProcessName">` fields
for HEC-ingested events, so `EventCode`, `Image`, `CommandLine`,
`GrantedAccess` and friends are missing and every field-based hunt is empty.

The dashboard's **Install field extraction** button writes:

- `/opt/splunk/etc/system/local/props.conf`
- `/opt/splunk/etc/system/local/transforms.conf`

inside the `splunk-soc` container (existing files are backed up as
`*.soc_lab.bak`) and reloads them. One dynamic regex maps every
`<Data Name="Field">value</Data>` pair, plus `EventID → EventCode`, `Channel`
and `Computer`. Run it again if the container volumes are recreated.

## Old YAML format

Some folders use the repo's older YAML layout (`dataset:` GitHub URLs instead of
`datasets:` paths). The UI labels these **legacy YAML**, maps each URL to the
matching local file, and infers `sourcetype`/`source` from the YAML hints and the
file contents (an XML `<Channel>` wins). Download the folder first.

## Configuration

Environment overrides (defaults match `docker-compose.yml`):

| Variable | Default |
|---|---|
| `SPLUNK_HOST` | `127.0.0.1` |
| `SPLUNK_PORT` | `8089` |
| `SPLUNK_WEB_PORT` | `8000` |
| `SPLUNK_USERNAME` | `admin` |
| `SPLUNK_PASSWORD` | `S0cPractice!2026` |
| `SPLUNK_CONTAINER` | `splunk-soc` |
| `SOC_INDEX` | `attack_data` |
| `SOC_COMPOSE_FILE` | `./docker-compose.yml` |
| `ATTACK_DATA_DIR` | `./attack_data` (or the parent checkout) |
| `ATTACK_DATA_REPO` | `https://github.com/splunk/attack_data.git` |

If you change `SPLUNK_PASSWORD` in `.env`, start the app with the same
`SPLUNK_PASSWORD` value. The HEC token is read through the Splunk API.

## Tests

```bash
.venv/bin/python test_app.py
```

Covers legacy YAML mapping, path-traversal rejection, the field-extraction merge
(idempotent), missing-checkout scanning, and the recipe file. No network or
Splunk access is required.

## Limits

- No ESCU runner: `security_content` detections need ESCU/ES macros and CIM data
  models that raw HEC replay does not provide. The built-in hunts are
  self-contained SPL instead.
- Replaying the same folder twice duplicates events.
- The server binds to `127.0.0.1` only; it can run arbitrary SPL and Docker
  commands for the local user.

## Layout

```
app.py                  server, Splunk client, dataset scanner, jobs
recipes.json            playbook hunts
splunk_config/          props.conf + transforms.conf installed into Splunk
ui/                     index.html, app.js, style.css (no build step)
docker-compose.yml      Splunk lab
docs/                   SOC practice and setup guides
test_app.py             unittest suite
```
