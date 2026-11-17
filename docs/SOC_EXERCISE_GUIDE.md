# SOC Exercise Guide — splunk/attack_data

**Goal:** Replay curated attack datasets into a local Splunk instance, run Splunk's own detection content (ESCU) against that data, and investigate the hits in Splunk Web.

This repo is **not** Splunk itself — it is attack data (logs) + helper scripts. You must supply a running Splunk instance. This guide runs Splunk inside Docker and points the replay/detection scripts at it.

> ⚠️ Disk warning: the full dataset is >9 GB (Git LFS). Pull **only** the technique folders you plan to exercise, not the whole repo.

---

## 0. Prerequisites

Install these on your host:

- **Docker** (to run Splunk)
- **git** + **git-lfs** (to fetch the repo and its large log files)
- **Python 3** + `venv` (to run `replay.py` and `run_escu_detections.py`)

```bash
# Debian/Ubuntu example
sudo apt-get update
sudo apt-get install -y docker.io git git-lfs python3 python3-venv python3-pip

# Add your user to the docker group so you can run docker without sudo
sudo usermod -aG docker $USER
newgrp docker
```

Verify:

```bash
docker --version
git lfs version
python3 --version
```

---

## 1. Clone the repo and pull only the datasets you need

Work inside your `splunk` folder (the empty repo folder you started in):

```bash
cd /home/arash/Desktop/VibeCodes/splunk
git clone --depth 1 --no-tags https://github.com/splunk/attack_data.git attack_data
cd attack_data
```

Install git-lfs (skip smudge so you don't download everything during clone):

```bash
git lfs install --skip-smudge
```

Now pull **one** technique folder as a practice dataset. Example: `T1003.001` (Credential Dumping) from Atomic Red Team:

```bash
# Pull just this technique's data (a few MB, not 9 GB)
git lfs pull --include="datasets/attack_techniques/T1003.001/atomic_red_team/"

# Confirm what landed locally
ls -la datasets/attack_techniques/T1003.001/atomic_red_team/
```

You should see `.yml` metadata files and `.log` data files (e.g. `windows-sysmon.log`, `4688_windows-security.log`).

> Repeat the `git lfs pull --include=...` step for any other MITRE technique you want to exercise later. To see available folders: `ls datasets/attack_techniques/`

---

## 2. Run Splunk inside Docker

Splunk publishes an official image: `splunk/splunk:latest`. We need three ports:

- `8000` — Splunk Web (investigation UI)
- `8088` — HTTP Event Collector (HEC) — `replay.py` sends data here
- `8089` — Splunk management (REST) — `run_escu_detections.py` queries detections here

Create a `docker-compose.yml` in the `splunk` folder:

```yaml
version: "3.8"
services:
  splunk:
    image: splunk/splunk:latest
    container_name: splunk-soc
    environment:
      SPLUNK_START_ARGS: "--accept-license"
      SPLUNK_PASSWORD: "S0cPractice!2026"   # change this
      SPLUNK_HEC_TOKEN: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"  # optional pre-seed
    ports:
      - "8000:8000"
      - "8088:8088"
      - "8089:8089"
    volumes:
      - splunk-etc:/opt/splunk/etc
      - splunk-var:/opt/splunk/var
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/en-US/account/login"]
      interval: 15s
      timeout: 5s
      retries: 20
volumes:
  splunk-etc:
  splunk-var:
```

Start it:

```bash
docker compose up -d
docker compose logs -f splunk   # watch until it says "Splunkd is running"
```

Wait for the healthcheck to pass (`docker compose ps` should show `healthy`), then open:

```
http://localhost:8000
```

Log in as `admin` / `S0cPractice!2026` (or whatever password you set).

> If you don't pre-seed `SPLUNK_HEC_TOKEN`, you will create the HEC token manually in step 3.

---

## 3. Create the HEC token and the `attack_data` index in Splunk

`replay.py` sends events to Splunk HEC and targets the index declared in each dataset YAML (default: `attack_data`). The ESCU runner talks to the REST API as `admin`.

### 3.1 Create the index

In Splunk Web:

1. **Settings → Indexes → New Index**
2. Index name: `attack_data`
3. Leave the rest default, click **Save**.

### 3.2 Create an HTTP Event Collector (HEC) token

1. **Settings → Data Inputs → HTTP Event Collector → New Token**
2. Name: `attack-data-replay`
3. **Indexes:** select `attack_data` (and `main` if you want)
4. Click **Next → Review → Submit**
5. **Copy the token value** — you need it for `SPLUNK_HEC_TOKEN`.
6. Make sure HEC is enabled globally: **Settings → Data Inputs → HTTP Event Collector → Global Settings → All tokens → Enabled**.

Set the env vars you will use for both scripts:

```bash
export SPLUNK_HOST="127.0.0.1"
export SPLUNK_HEC_TOKEN="<PASTE_YOUR_HEC_TOKEN_HERE>"
export SPLUNK_USERNAME="admin"
export SPLUNK_PASSWORD="S0cPractice!2026"
export SPLUNK_PORT="8089"
export SPLUNK_VERIFY_SSL="false"
```

Persist them (optional):

```bash
cat >> ~/.bashrc << 'EOF'
export SPLUNK_HOST="127.0.0.1"
export SPLUNK_HEC_TOKEN="<PASTE_YOUR_HEC_TOKEN_HERE>"
export SPLUNK_USERNAME="admin"
export SPLUNK_PASSWORD="S0cPractice!2026"
export SPLUNK_PORT="8089"
export SPLUNK_VERIFY_SSL="false"
EOF
source ~/.bashrc
```

---

## 4. Set up the Python environment for the helper scripts

```bash
cd /home/arash/Desktop/VibeCodes/splunk/attack_data

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r bin/requirements.txt
```

`bin/requirements.txt` contains the Python deps for `replay.py`; `run_escu_detections.py` additionally needs `splunklib`, `gitpython`, `tqdm`, `colorama`, `pyyaml`. Install them too:

```bash
pip install splunklib gitpython tqdm colorama pyyaml requests urllib3
```

---

## 5. Replay attack data into Splunk

Use `bin/replay.py`. It reads YAML metadata (index/source/sourcetype) from each dataset and posts the raw log file to HEC.

### 5.1 Replay a single technique (recommended first run)

```bash
cd /home/arash/Desktop/VibeCodes/splunk/attack_data
source venv/bin/activate

python bin/replay.py datasets/attack_techniques/T1003.001/atomic_red_team/
```

Example output:

```
Found 3 YAML files to process

Processing datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.yml...
:white_check_mark: Sent windows-sysmon.log to Splunk HEC
...
```

### 5.2 Replay a single YAML file

```bash
python bin/replay.py datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.yml
```

### 5.3 Replay multiple techniques at once

```bash
python bin/replay.py \
  datasets/attack_techniques/T1003.001/atomic_red_team/ \
  datasets/attack_techniques/T1059/atomic_red_team/
```

### 5.4 Override metadata (optional)

If you want everything in one index/source regardless of what the YAML says:

```bash
python bin/replay.py datasets/attack_techniques/T1003.001/atomic_red_team/ \
  --index-override attack_data \
  --source-override atomic_red_team \
  --sourcetype-override XmlWinEventLog \
  --host-uuid lab-host-01
```

---

## 6. Verify data landed in Splunk

Open **http://localhost:8000** → **Search & Reporting** and run:

```splunk
index=attack_data
| head 100
```

You should see events with `sourcetype` values like `XmlWinEventLog` and `source` values matching the dataset YAML.

Splunk search examples to start your SOC exercise:

```splunk
# All attack data, latest first
index=attack_data | sort -_time | head 200

# Count events per sourcetype
index=attack_data | stats count by sourcetype

# PowerShell execution (T1059.001) style events
index=attack_data sourcetype=XmlWinEventLog "powershell"

# Command-line process creation (Event Code 4688)
index=attack_data source="XmlWinEventLog:Security" EventCode=4688
| stats count by ProcessName, ProcessCommandLine
```

> Splunk may take ~30–60 seconds to index freshly HEC'd events. If a search returns nothing, wait and retry.

---

## 7. Run Splunk ESCU detections against the replayed data

`bin/run_escu_detections.py` clones `splunk/security_content` (Splunk's detection content) and executes every production detection against your Splunk instance via the REST API (port 8089).

### 7.1 First run — all production detections, last 24 hours

```bash
cd /home/arash/Desktop/VibeCodes/splunk/attack_data
source venv/bin/activate

python bin/run_escu_detections.py \
  --time-range "-24h,now" \
  --max-results 1000 \
  --filter-status production \
  --output-report escu_report.txt \
  --output-json escu_results.json \
  --verbose
```

This:
1. Clones `security_content` into `./security_content` (inside `attack_data/`).
2. Parses every detection YAML.
3. Runs each SPL search against your local Splunk.
4. Writes `escu_report.txt` (summary) and `escu_results.json` (details).

### 7.2 Run only detections relevant to the technique you replayed

Example: after replaying `T1003.001` (Credential Dumping):

```bash
python bin/run_escu_detections.py \
  --time-range "-24h,now" \
  --filter-mitre T1003 \
  --filter-status production \
  --output-report escu_t1003_report.txt \
  --output-json escu_t1003_results.json
```

### 7.3 Run a detection family only

```bash
python bin/run_escu_detections.py \
  --time-range "-7d,now" \
  --filter-type "TTP Hunting Correlation" \
  --output-report escu_ttp_report.txt
```

### 7.4 Inspect the results

```bash
cat escu_report.txt
```

Open `escu_results.json` to see which detections fired, the SPL used, and result counts. Any detection with `result_count > 0` is a potential alert to triage in Splunk Web.

---

## 8. Triage a detection hit in Splunk Web

When a detection fires, copy its SPL query from the JSON report into **Search & Reporting** and run it over `index=attack_data`. Example investigative flow:

```splunk
# 1. See what the detection matched
index=attack_data <paste_detection_spl_here>
| table _time, host, sourcetype, source, ProcessName, ProcessCommandLine, User, Dest
| sort -_time

# 2. Build a timeline around the first hit
index=attack_data host="<host_from_hit>"
| sort _time
| table _time, sourcetype, source, EventCode, ProcessCommandLine
```

Treat each hit like a real alert: confirm true/false positive, identify the technique, and document your findings.

---

## 9. Optional — TOTAL-REPLAY

`total_replay/` is a separate lightweight tool (Python + Poetry) that uses Splunk Security Content metadata (detection names, analytic stories) to pick relevant attack logs and replay them. See `total_replay/readme.md` for its own setup; it is not required for the basic exercise above.

---

## Cheat-sheet: commands in order

```bash
# 0. Prereqs (once)
sudo apt-get install -y docker.io git git-lfs python3 python3-venv python3-pip
sudo usermod -aG docker $USER && newgrp docker

# 1. Clone + pull one dataset
cd /home/arash/Desktop/VibeCodes/splunk
git clone --depth 1 --no-tags https://github.com/splunk/attack_data.git attack_data
cd attack_data
git lfs install --skip-smudge
git lfs pull --include="datasets/attack_techniques/T1003.001/atomic_red_team/"

# 2. Splunk in Docker
cat > docker-compose.yml << 'EOF'
... (paste the compose from section 2) ...
EOF
docker compose up -d
docker compose ps   # wait for healthy

# 3. Splunk Web: create index "attack_data" + HEC token "attack-data-replay"
#    then copy the HEC token value

export SPLUNK_HOST="127.0.0.1"
export SPLUNK_HEC_TOKEN="<your-hec-token>"
export SPLUNK_USERNAME="admin"
export SPLUNK_PASSWORD="S0cPractice!2026"
export SPLUNK_PORT="8089"
export SPLUNK_VERIFY_SSL="false"

# 4. Python env + replay
python3 -m venv venv && source venv/bin/activate
pip install -r bin/requirements.txt
pip install splunklib gitpython tqdm colorama pyyaml requests urllib3
python bin/replay.py datasets/attack_techniques/T1003.001/atomic_red_team/

# 5. Verify in Splunk Web: index=attack_data | head 100

# 6. Run ESCU detections
python bin/run_escu_detections.py --time-range "-24h,now" --filter-mitre T1003

# 7. Investigate hits in Splunk Web
```

---

## Troubleshooting / known limits

| Issue | Fix |
|-------|-----|
| `HEC code 7` | Index `attack_data` doesn't exist. Create it in Splunk Web or use `--index-override <existing_index>`. |
| `HEC code 4` | Invalid HEC token. Re-copy the token from Settings → Data Inputs → HEC and confirm it is enabled. |
| `replay.py` finds no YAML files | You didn't `git lfs pull` that folder, or the path is wrong. |
| ESCU runner returns 0 results | Time range too narrow, or data not yet indexed. Wait a minute and widen to `-7d,now`. |
| Docker port already in use | Change the left side of the port mapping, e.g. `8001:8000`. |

**Shortcut:** this guide pulls one technique and runs ESCU filtered by that MITRE ID — it is the smallest complete loop for a SOC exercise. Expand to more techniques by repeating steps 1 (LFS pull), 5 (replay), and 7 (detections).

```
cd /home/arash/Desktop/VibeCodes/splunk/attack_data
source venv/bin/activate
python bin/run_escu_detections.py --time-range "-24h,now" --filter-mitre T1003 --filter-status production
```
