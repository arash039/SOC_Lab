#!/usr/bin/env python3
"""SOC Lab - a local web UI for splunk/attack_data + Splunk.

Setup:
    python3 -m venv .venv
    .venv/bin/pip install -r requirements.txt
    .venv/bin/python app.py

Everything is read from a local attack_data checkout (cloned on demand from the
UI); no data leaves the machine except the git-lfs download you trigger.
"""

import argparse
import errno
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import webbrowser
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

try:
    import requests
    import yaml
except ImportError:
    sys.exit(
        "Missing dependencies. Create the project virtualenv first:\n"
        "  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
    )

import urllib3

urllib3.disable_warnings()

APP_DIR = Path(__file__).resolve().parent
LAB_ROOT = APP_DIR.parent
LOCAL_ATTACK_DATA = APP_DIR / "attack_data"
REPO_URL = os.environ.get("ATTACK_DATA_REPO", "https://github.com/splunk/attack_data.git")


def discover_attack_data():
    configured = os.environ.get("ATTACK_DATA_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    if LOCAL_ATTACK_DATA.exists():
        return LOCAL_ATTACK_DATA.resolve()
    return (LAB_ROOT / "attack_data").resolve()


ATTACK_DATA = discover_attack_data()
DATASETS_DIR = ATTACK_DATA / "datasets"
REPLAY_PY = ATTACK_DATA / "bin" / "replay.py"
UI_DIR = APP_DIR / "ui"
CONFIG_DIR = APP_DIR / "splunk_config"


def refresh_paths():
    global ATTACK_DATA, DATASETS_DIR, REPLAY_PY
    ATTACK_DATA = discover_attack_data()
    DATASETS_DIR = ATTACK_DATA / "datasets"
    REPLAY_PY = ATTACK_DATA / "bin" / "replay.py"


SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "127.0.0.1")
SPLUNK_PORT = int(os.environ.get("SPLUNK_PORT", "8089"))
SPLUNK_WEB_PORT = int(os.environ.get("SPLUNK_WEB_PORT", "8000"))
SPLUNK_USER = os.environ.get("SPLUNK_USERNAME", "admin")
SPLUNK_PASSWORD = os.environ.get("SPLUNK_PASSWORD", "S0cPractice!2026")
INDEX = os.environ.get("SOC_INDEX", "attack_data")
CONTAINER = os.environ.get("SPLUNK_CONTAINER", "splunk-soc")

SPLUNK_URL = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"
WEB_URL = f"http://{SPLUNK_HOST}:{SPLUNK_WEB_PORT}"

FIELD_MARKER = "REPORT-soc_attack_xml"
FIELD_PROPS = CONFIG_DIR / "props.conf"
FIELD_TRANSFORMS = CONFIG_DIR / "transforms.conf"

TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
HOST_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
LFS_POINTER = b"version https://git-lfs.github.com/spec/v1"
DATA_SUFFIXES = {".log", ".json", ".txt", ".csv", ".xml", ".zip", ".gz", ".evtx"}

RANGES = {
    "15m": ("-15m", "now"),
    "1h": ("-1h", "now"),
    "24h": ("-24h", "now"),
    "7d": ("-7d", "now"),
    "30d": ("-30d", "now"),
    "all": ("0", ""),
}


class SplunkError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# Splunk REST helpers
# --------------------------------------------------------------------------- #


def splunk_request(method, path, timeout=20, **kwargs):
    return requests.request(
        method,
        f"{SPLUNK_URL}{path}",
        auth=(SPLUNK_USER, SPLUNK_PASSWORD),
        verify=False,
        timeout=timeout,
        **kwargs,
    )


def response_error(resp):
    try:
        messages = resp.json().get("messages", [])
    except ValueError:
        messages = []
    text = " | ".join(m.get("text", "") for m in messages if m.get("text"))
    return text or (resp.text or resp.reason or f"HTTP {resp.status_code}")[:400]


def ensure_index():
    try:
        resp = splunk_request("GET", f"/services/data/indexes/{INDEX}", timeout=10)
    except requests.RequestException as exc:
        raise SplunkError(f"Splunk is not reachable at {SPLUNK_URL}: {exc}") from exc
    if resp.status_code == 200:
        return
    if resp.status_code != 404:
        raise SplunkError(f"Could not check index {INDEX}: {response_error(resp)}")
    created = splunk_request(
        "POST", "/services/data/indexes", data={"name": INDEX, "output_mode": "json"}, timeout=30
    )
    if created.status_code not in (200, 201):
        raise SplunkError(f"Could not create index {INDEX}: {response_error(created)}")


def ensure_hec_token():
    try:
        return get_hec_token()
    except SplunkError:
        enabled = splunk_request(
            "POST",
            "/services/data/inputs/http/http",
            data={"disabled": "0", "enableSSL": "1", "output_mode": "json"},
            timeout=15,
        )
        if enabled.status_code not in (200, 201):
            raise SplunkError(f"Could not enable HEC: {response_error(enabled)}")
        created = splunk_request(
            "POST",
            "/services/data/inputs/http",
            data={
                "name": "attack-data-replay",
                "indexes": INDEX,
                "disabled": "0",
                "output_mode": "json",
            },
            timeout=30,
        )
        if created.status_code not in (200, 201):
            raise SplunkError(f"Could not create an HEC token: {response_error(created)}")
        return get_hec_token()


def ensure_splunk_ready():
    ensure_index()
    return ensure_hec_token()


def ensure_delete_capability(job):
    try:
        resp = splunk_request(
            "GET", f"/services/authentication/users/{SPLUNK_USER}", params={"output_mode": "json"}
        )
    except requests.RequestException as exc:
        raise SplunkError(f"Splunk is not reachable at {SPLUNK_URL}: {exc}") from exc
    if resp.status_code != 200:
        raise SplunkError(f"Could not read user {SPLUNK_USER}: {response_error(resp)}")
    roles = resp.json()["entry"][0]["content"].get("roles") or []
    if "can_delete" in roles:
        return
    data = [("roles", role) for role in roles]
    data.append(("roles", "can_delete"))
    data.append(("output_mode", "json"))
    updated = splunk_request("POST", f"/services/authentication/users/{SPLUNK_USER}", data=data)
    if updated.status_code not in (200, 201):
        raise SplunkError(
            "Event deletion needs the can_delete role. Ask an administrator to add it: "
            f"{response_error(updated)}"
        )
    job.log(f"Granted the can_delete role to {SPLUNK_USER} (required by Splunk's delete command).")


def event_count(job, host=None):
    query = f"index={INDEX} | stats count"
    if host:
        query = f'index={INDEX} host="{host}" | stats count'
    rows = splunk_search(query, earliest="0", limit=1)["rows"]
    return int(float(rows[0].get("count") or 0)) if rows else 0


def delete_events(job, host=None):
    ensure_delete_capability(job)
    label = f"host {host}" if host else f"index {INDEX}"
    before = event_count(job, host)
    if before == 0:
        job.log(f"No events to delete for {label}.")
        return
    job.log(f"Deleting {before} events for {label}...")
    query = f"index={INDEX} | delete"
    if host:
        query = f'index={INDEX} host="{host}" | delete'
    splunk_search(query, earliest="0", limit=1)
    deadline = time.time() + 120
    remaining = before
    while time.time() < deadline:
        remaining = event_count(job, host)
        if remaining == 0:
            break
        time.sleep(2)
    if remaining:
        job.log(
            f"Delete was accepted, but {remaining} events are still visible. "
            "Splunk may need more time; refresh in a minute."
        )
    else:
        job.log(f"Deleted all events for {label}.")
    job.log("Splunk reclaims disk space when buckets roll or trim.")


def get_hec_token():
    try:
        resp = splunk_request("GET", "/services/data/inputs/http", params={"output_mode": "json"})
    except requests.RequestException as exc:
        raise SplunkError(f"Splunk is not reachable at {SPLUNK_URL}: {exc}") from exc
    if resp.status_code != 200:
        raise SplunkError(f"Could not read HEC inputs: {response_error(resp)}")
    fallback = None
    for entry in resp.json().get("entry", []):
        content = entry.get("content", {})
        token = content.get("token")
        if content.get("disabled") or not token:
            continue
        raw_indexes = content.get("indexes") or []
        if isinstance(raw_indexes, str):
            raw_indexes = raw_indexes.split(",")
        indexes = {str(part).strip() for part in raw_indexes if str(part).strip()}
        if not indexes or INDEX in indexes or "*" in indexes:
            return token
        fallback = fallback or token
    if fallback:
        raise SplunkError(f"No enabled HEC token allows index {INDEX}.")
    raise SplunkError(
        "No enabled HTTP Event Collector token found. Create one in Splunk: "
        "Settings > Data Inputs > HTTP Event Collector."
    )


def splunk_search(spl, earliest="0", latest="", limit=200):
    query = (spl or "").strip()
    if not query:
        raise SplunkError("The search is empty.")
    if not query.startswith("|"):
        query = "search " + query

    try:
        created = splunk_request(
            "POST",
            "/services/search/jobs",
            timeout=30,
            data={
                "search": query,
                "earliest_time": earliest,
                "latest_time": latest,
                "output_mode": "json",
                "exec_mode": "normal",
            },
        )
    except requests.RequestException as exc:
        raise SplunkError(f"Splunk is not reachable at {SPLUNK_URL}: {exc}") from exc

    if created.status_code not in (200, 201):
        raise SplunkError(response_error(created))
    sid = created.json().get("sid")
    if not sid:
        raise SplunkError("Splunk did not return a search id.")

    started = time.time()
    state = "QUEUED"
    messages = []
    try:
        deadline = time.time() + 180
        while time.time() < deadline:
            try:
                job = splunk_request(
                    "GET", f"/services/search/jobs/{sid}", params={"output_mode": "json"}, timeout=15
                ).json()
            except (requests.RequestException, ValueError) as exc:
                raise SplunkError(f"Lost connection to Splunk while searching: {exc}") from exc
            content = job.get("entry", [{}])[0].get("content", {})
            state = content.get("dispatchState") or state
            messages = content.get("messages") or messages
            if content.get("isDone") or state in ("DONE", "FAILED"):
                break
            time.sleep(0.3)
        else:
            raise SplunkError("Search timed out after 180 seconds.")

        if state == "FAILED":
            errors = [m.get("text", "") for m in messages if m.get("type") in ("FATAL", "ERROR")]
            raise SplunkError(" | ".join(errors) or "Splunk reported the search as failed.")

        result = splunk_request(
            "GET",
            f"/services/search/jobs/{sid}/results",
            params={"output_mode": "json", "count": max(1, min(int(limit), 1000)), "offset": 0},
            timeout=60,
        )
        if result.status_code != 200:
            raise SplunkError(response_error(result))
        payload = result.json()
        rows = payload.get("results") or []
        raw_fields = payload.get("fields") or []
        fields = [
            item.get("name") if isinstance(item, dict) else item
            for item in raw_fields
        ]
        fields = [field for field in fields if field]
        if not fields and rows:
            fields = list(rows[0].keys())
        return {
            "fields": fields,
            "rows": rows,
            "truncated": len(rows) >= int(limit),
            "elapsed": round(time.time() - started, 2),
        }
    finally:
        try:
            splunk_request("DELETE", f"/services/search/jobs/{sid}", timeout=5)
        except requests.RequestException:
            pass


# --------------------------------------------------------------------------- #
# Dataset scanning
# --------------------------------------------------------------------------- #


def is_lfs_pointer(path):
    try:
        with open(path, "rb") as handle:
            return handle.read(len(LFS_POINTER)) == LFS_POINTER
    except OSError:
        return False


def dataset_path_from_yml(raw):
    if not isinstance(raw, str) or not raw.strip():
        return None
    raw = raw.strip()
    if raw.startswith("/datasets/"):
        return (ATTACK_DATA / raw.lstrip("/")).resolve()
    if raw.startswith("datasets/"):
        return (ATTACK_DATA / raw).resolve()
    return None


def inside_datasets(path):
    try:
        path.resolve().relative_to(DATASETS_DIR.resolve())
        return True
    except ValueError:
        return False


def local_data_files(folder):
    try:
        return sorted(
            path
            for path in folder.iterdir()
            if path.is_file() and path.suffix.lower() in DATA_SUFFIXES
        )
    except OSError:
        return []


def format_bytes(size):
    size = float(size or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" or size >= 10 else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.0f} GB"



def tempfile_dir():
    directory = Path("/tmp/opencode")
    directory.mkdir(parents=True, exist_ok=True)
    return str(directory)


def safe_dataset_dir(rel):
    if not isinstance(rel, str) or not rel.strip():
        raise ValueError("Missing dataset folder.")
    rel = rel.strip().strip("/")
    if not all(SAFE_SEGMENT_RE.match(part) for part in rel.split("/")):
        raise ValueError(f"Unsafe dataset path: {rel}")
    target = (DATASETS_DIR / rel).resolve()
    if not inside_datasets(target) or not target.is_dir():
        raise ValueError(f"No such dataset folder: {rel}")
    return target


def pretty_label(rel):
    return rel.rsplit("/", 1)[-1].replace("_", " ").replace("-", " ")


_scan = {"ts": 0.0, "groups": [], "by_path": {}, "by_host": {}}
_scan_lock = threading.Lock()
SCAN_TTL = 20


def build_scan():
    groups = {}
    if not DATASETS_DIR.is_dir():
        return {"ts": time.time(), "groups": [], "by_path": {}, "by_host": {}}
    ymls = sorted(list(DATASETS_DIR.rglob("*.yml")) + list(DATASETS_DIR.rglob("*.yaml")))
    for yml in ymls:
        if yml.name.lower() == "template.yml":
            continue
        try:
            doc = yaml.safe_load(yml.read_text(encoding="utf-8", errors="replace"))
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(doc, dict):
            continue
        rel = yml.parent.relative_to(DATASETS_DIR).as_posix()
        group = groups.setdefault(
            rel,
            {
                "path": rel,
                "ymls": [],
                "techniques": set(),
                "hosts": set(),
                "descriptions": [],
                "environment": "",
                "files": [],
                "file_keys": set(),
                "legacy": False,
                "mtime": 0.0,
            },
        )
        group["ymls"].append(yml.name)
        try:
            group["mtime"] = max(group["mtime"], yml.stat().st_mtime)
        except OSError:
            pass

        technique = doc.get("mitre_technique") or []
        if isinstance(technique, str):
            technique = [technique]
        for item in technique:
            if isinstance(item, str) and item.strip():
                group["techniques"].add(item.strip())

        host = doc.get("id")
        if isinstance(host, str) and HOST_RE.match(host.strip()):
            group["hosts"].add(host.strip())

        description = doc.get("description")
        if isinstance(description, str) and description.strip():
            group["descriptions"].append(description.strip())
        if doc.get("environment") and not group["environment"]:
            group["environment"] = str(doc.get("environment"))

        declared = doc.get("datasets")
        if doc.get("dataset") and not declared:
            group["legacy"] = True

        for entry in declared or []:
            if not isinstance(entry, dict):
                continue
            path = dataset_path_from_yml(entry.get("path"))
            if path is None or not inside_datasets(path):
                continue
            key = str(path)
            if key in group["file_keys"]:
                continue
            group["file_keys"].add(key)
            exists = path.is_file()
            size = path.stat().st_size if exists else 0
            group["files"].append(
                {
                    "name": str(entry.get("name") or path.name),
                    "file": path.name,
                    "sourcetype": str(entry.get("sourcetype") or ""),
                    "source": str(entry.get("source") or ""),
                    "bytes": size,
                    "exists": exists,
                    "pointer": exists and is_lfs_pointer(path),
                }
            )

    for group in groups.values():
        if not group["techniques"]:
            group["techniques"] = set(TECH_RE.findall(group["path"]))
        files = group["files"]
        present = [f for f in files if f["exists"]]
        real = [f for f in present if not f["pointer"]]
        if not files:
            state = "legacy" if group["legacy"] else "unknown"
        elif len(real) == len(files):
            state = "ready"
        elif present:
            state = "partial"
        else:
            state = "missing"
        group["state"] = state
        group["label"] = pretty_label(group["path"])
        if group["techniques"]:
            group["label"] = f'{sorted(group["techniques"])[0]} · {pretty_label(group["path"])}'
        group["category"] = group["path"].split("/", 1)[0]
        group["technique_list"] = sorted(group["techniques"])
        group["host_list"] = sorted(group["hosts"])
        description = max(group["descriptions"], key=len) if group["descriptions"] else ""
        group["description"] = " ".join(description.split())[:600]
        group["bytes"] = sum(f["bytes"] for f in present)
        group["file_count"] = len(files)
        group["ready_files"] = len(real)
        group["local_files"] = [path.name for path in local_data_files(DATASETS_DIR / group["path"])]
        group["ymls"] = sorted(set(group["ymls"]))
        del group["file_keys"]

    by_path = {group["path"]: group for group in groups.values()}
    by_host = {}
    for group in groups.values():
        for host in group["hosts"]:
            by_host.setdefault(host, []).append(group["path"])
    return {
        "ts": time.time(),
        "groups": sorted(groups.values(), key=lambda g: g["path"]),
        "by_path": by_path,
        "by_host": by_host,
    }


def get_scan(force=False):
    with _scan_lock:
        if force or time.time() - _scan["ts"] > SCAN_TTL or not _scan["groups"]:
            _scan.update(build_scan())
        return _scan


def invalidate_scan():
    with _scan_lock:
        _scan["ts"] = 0.0


def public_group(group):
    return {
        "path": group["path"],
        "label": group["label"],
        "category": group["category"],
        "techniques": group["technique_list"],
        "hosts": group["host_list"],
        "state": group["state"],
        "file_count": group["file_count"],
        "ready_files": group["ready_files"],
        "bytes": group["bytes"],
        "description": group["description"],
        "ymls": len(group["ymls"]),
        "legacy": group["legacy"],
        "local_count": len(group["local_files"]),
        "updated": group["mtime"],
    }


# --------------------------------------------------------------------------- #
# Lab status
# --------------------------------------------------------------------------- #


def docker_status():
    try:
        proc = subprocess.run(
            ["docker", "ps", "--filter", f"name={CONTAINER}", "--format", "{{.Status}}"],
            capture_output=True,
            text=True,
            timeout=8,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "running": False, "detail": str(exc), "container": CONTAINER}
    detail = proc.stdout.strip()
    error = proc.stderr.strip()
    return {
        "available": proc.returncode == 0,
        "running": bool(detail) and detail.lower().startswith("up"),
        "detail": detail or error or "container not found",
        "container": CONTAINER,
    }


def compose_file():
    configured = os.environ.get("SOC_COMPOSE_FILE")
    if configured:
        return Path(configured).expanduser().resolve()
    repo_file = APP_DIR / "docker-compose.yml"
    if repo_file.exists():
        return repo_file
    return LAB_ROOT / "docker-compose.yml"


def compose_project_dir():
    file = compose_file()
    parent_file = LAB_ROOT / "docker-compose.yml"
    # Keep the existing project name/volumes when the lab also lives in the
    # parent directory (the development layout), even though the repo copy is
    # the canonical compose file.
    if file.parent == APP_DIR and parent_file.exists():
        return LAB_ROOT
    return file.parent


def repo_status():
    local = LOCAL_ATTACK_DATA.resolve()
    return {
        "ready": DATASETS_DIR.is_dir(),
        "path": str(ATTACK_DATA),
        "url": REPO_URL,
        "local_path": str(local),
        "using_parent_checkout": ATTACK_DATA == (LAB_ROOT / "attack_data").resolve(),
    }



def fields_installed():
    try:
        proc = subprocess.run(
            [
                "docker",
                "exec",
                "-u",
                "root",
                CONTAINER,
                "sh",
                "-c",
                "grep -q REPORT-soc_attack_xml /opt/splunk/etc/system/local/props.conf "
                "&& grep -q soc_attack_xml_eventid /opt/splunk/etc/system/local/transforms.conf",
            ],
            capture_output=True,
            text=True,
            timeout=8,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def get_status():
    status = {
        "ok": False,
        "index": INDEX,
        "web_url": WEB_URL,
        "api_url": SPLUNK_URL,
        "splunk": {"reachable": False},
        "docker": docker_status(),
        "hec": {"ok": False},
        "fields": {"installed": fields_installed(), "verified": None},
        "repo": repo_status(),
        "compose": {"file": str(compose_file()), "exists": compose_file().exists()},
        "data": {"events": 0, "sourcetypes": [], "hosts": 0},
        "loaded": [],
        "error": "",
    }
    try:
        info = splunk_request("GET", "/services/server/info", params={"output_mode": "json"}, timeout=6)
    except requests.RequestException as exc:
        status["error"] = f"Splunk is not reachable at {SPLUNK_URL}: {exc}"
        return status
    if info.status_code != 200:
        status["error"] = response_error(info)
        return status
    content = info.json()["entry"][0]["content"]
    status["splunk"] = {
        "reachable": True,
        "version": content.get("version"),
        "name": content.get("serverName"),
        "license": content.get("licenseState"),
    }
    status["ok"] = True

    try:
        indexes = splunk_request(
            "GET", f"/services/data/indexes/{INDEX}", params={"output_mode": "json"}, timeout=8
        )
        status["index_exists"] = indexes.status_code == 200
    except requests.RequestException:
        status["index_exists"] = None

    try:
        token = get_hec_token()
        status["hec"] = {"ok": bool(token)}
    except SplunkError as exc:
        status["hec"] = {"ok": False, "error": str(exc)}

    try:
        counts = splunk_search(
            f"index={INDEX} | stats count by host sourcetype", earliest="0", limit=5000
        )
        by_host = {}
        by_sourcetype = {}
        for row in counts["rows"]:
            host = row.get("host") or "(no host)"
            sourcetype = row.get("sourcetype") or "(no sourcetype)"
            count = int(float(row.get("count") or 0))
            by_host[host] = by_host.get(host, 0) + count
            by_sourcetype[sourcetype] = by_sourcetype.get(sourcetype, 0) + count
        status["data"] = {
            "events": sum(by_host.values()),
            "hosts": len(by_host),
            "sourcetypes": sorted(
                [{"name": k, "count": v} for k, v in by_sourcetype.items()],
                key=lambda item: -item["count"],
            ),
        }
        scan = get_scan()
        for host, count in sorted(by_host.items(), key=lambda item: -item[1]):
            paths = scan["by_host"].get(host, [])
            group = scan["by_path"].get(paths[0]) if paths else None
            status["loaded"].append(
                {
                    "host": host,
                    "count": count,
                    "path": group["path"] if group else None,
                    "label": group["label"] if group else host,
                    "techniques": group["technique_list"] if group else [],
                    "paths": paths,
                }
            )
    except SplunkError as exc:
        status["data_error"] = str(exc)

    if status["fields"]["installed"] and status["data"]["events"]:
        try:
            probe = splunk_search(
                f"index={INDEX} sourcetype=XmlWinEventLog | head 1 | table EventCode",
                earliest="0",
                limit=1,
            )
            status["fields"]["verified"] = bool(probe["rows"]) and "EventCode" in probe["rows"][0]
        except SplunkError:
            status["fields"]["verified"] = None
    return status


# --------------------------------------------------------------------------- #
# Jobs
# --------------------------------------------------------------------------- #


class Job:
    def __init__(self, title, kind):
        self.id = uuid.uuid4().hex[:8]
        self.title = title
        self.kind = kind
        self.status = "running"
        self.started = time.time()
        self.ended = None
        self.returncode = None
        self.output = deque(maxlen=800)
        self.lock = threading.Lock()

    def log(self, line):
        with self.lock:
            self.output.append(str(line).rstrip())

    def snapshot(self):
        with self.lock:
            return {
                "id": self.id,
                "title": self.title,
                "kind": self.kind,
                "status": self.status,
                "started": self.started,
                "ended": self.ended,
                "returncode": self.returncode,
                "output": "\n".join(self.output),
            }


JOBS = {}
JOBS_LOCK = threading.Lock()


def run_command(job, argv, cwd=None, env=None):
    job.log("$ " + " ".join(shlex.quote(str(part)) for part in argv))
    try:
        proc = subprocess.Popen(
            argv,
            cwd=str(cwd) if cwd else None,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except OSError as exc:
        raise RuntimeError(f"Could not start {argv[0]}: {exc}") from exc
    for line in proc.stdout:
        job.log(line.rstrip())
    code = proc.wait()
    if code != 0:
        raise RuntimeError(f"Command failed with exit code {code}")
    return code


def start_job(title, kind, runner, on_done=None):
    job = Job(title, kind)
    with JOBS_LOCK:
        JOBS[job.id] = job

    def target():
        try:
            runner(job)
            job.status = "done"
        except Exception as exc:  # surface any failure in the UI log
            job.log(f"ERROR: {exc}")
            job.status = "failed"
            job.returncode = 1
        finally:
            job.ended = time.time()
            invalidate_scan()
            if on_done:
                try:
                    on_done(job)
                except Exception:
                    pass

    threading.Thread(target=target, daemon=True).start()
    return job


def wait_for_splunk(job, timeout=300):
    job.log("Waiting for Splunk REST API...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if splunk_request("GET", "/services/server/info", timeout=4).status_code == 200:
                job.log("Splunk is up.")
                return
        except requests.RequestException:
            pass
        time.sleep(3)
    raise RuntimeError("Splunk did not come back within 5 minutes. Check docker logs splunk-soc.")


# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #


def make_repo_runner():
    def runner(job):
        if DATASETS_DIR.is_dir():
            job.log(f"attack_data is already available at {ATTACK_DATA}")
            return
        target = ATTACK_DATA if os.environ.get("ATTACK_DATA_DIR") else LOCAL_ATTACK_DATA
        if target.exists() and any(target.iterdir()):
            raise RuntimeError(
                f"{target} exists but is not a complete attack_data checkout. "
                "Move it away and retry."
            )
        lfs = subprocess.run(["git", "lfs", "version"], capture_output=True, text=True)
        if lfs.returncode != 0:
            raise RuntimeError(
                "git-lfs is required to download attack datasets. Install it first "
                "(e.g. sudo apt install git-lfs)."
            )
        env = os.environ.copy()
        env["GIT_LFS_SKIP_SMUDGE"] = "1"
        run_command(
            job,
            ["git", "clone", "--depth", "1", "--no-tags", REPO_URL, str(target)],
            cwd=APP_DIR,
            env=env,
        )
        run_command(
            job,
            ["git", "-C", str(target), "lfs", "install", "--local", "--skip-smudge"],
            env=env,
        )
        refresh_paths()
        invalidate_scan()
        job.log("")
        job.log("Repository cloned without its LFS logs.")
        job.log("Open Datasets and press Download on one technique to fetch only that folder.")

    return runner


def make_delete_download_runner(rel):
    def runner(job):
        folder = safe_dataset_dir(rel)
        files = local_data_files(folder)
        if not files:
            job.log("No downloaded data files in this folder.")
            return
        total = 0
        for path in files:
            size = 0 if path.is_symlink() else path.stat().st_size
            path.unlink()
            total += size
            job.log(f"Removed {path.name}")
        invalidate_scan()
        job.log("")
        job.log(
            f"Freed {format_bytes(total)}. YAML metadata is kept; use Download to restore the data."
        )

    return runner


def make_delete_replay_runner(hosts):
    def runner(job):
        if not hosts:
            raise RuntimeError("This dataset has no declared host id to delete.")
        for host in hosts:
            if not HOST_RE.match(host):
                raise RuntimeError(f"Refusing to delete with an invalid host value: {host}")
            delete_events(job, host)

    return runner


def make_delete_all_replay_runner():
    def runner(job):
        delete_events(job)

    return runner


def make_remove_repo_runner():
    def runner(job):
        local = LOCAL_ATTACK_DATA.resolve()
        if ATTACK_DATA.resolve() != local:
            raise RuntimeError(
                "Refusing to delete a checkout the app does not manage. "
                "Only ./attack_data can be removed from here."
            )
        if not local.exists():
            job.log("attack_data is already absent.")
            return
        job.log(f"Removing {local} ...")
        if local.is_symlink():
            local.unlink()
        else:
            shutil.rmtree(local)
        refresh_paths()
        invalidate_scan()
        job.log("Removed the local attack_data checkout. Clone it again when needed.")

    return runner


def restore_tracked_data_files(job, rel):
    proc = subprocess.run(
        ["git", "-C", str(ATTACK_DATA), "ls-tree", "-r", "--name-only", "HEAD", "--", f"datasets/{rel}"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return
    for repo_path in proc.stdout.splitlines():
        path = ATTACK_DATA / repo_path
        if not path.is_file() and path.suffix.lower() in DATA_SUFFIXES:
            job.log(f"Restoring tracked file {path.name}")
            run_command(job, ["git", "-C", str(ATTACK_DATA), "checkout", "HEAD", "--", repo_path])


def make_download_runner(rel):
    def runner(job):
        if not DATASETS_DIR.is_dir():
            raise RuntimeError(
                "attack_data is not available. Clone the repository from the dashboard first."
            )
        restore_tracked_data_files(job, rel)
        run_command(
            job,
            ["git", "-C", str(ATTACK_DATA), "lfs", "pull", f"--include=datasets/{rel}/*"],
        )
        invalidate_scan()
        group = get_scan(force=True)["by_path"].get(rel)
        if group:
            pending = [f["file"] for f in group["files"] if not f["exists"] or f["pointer"]]
            if pending:
                job.log(f"Still not available: {', '.join(pending)}")
                job.log("The dataset YAML may reference a file that is not tracked in git.")
            else:
                job.log("Dataset files are available locally.")

    return runner


def load_yml_docs(folder):
    docs = []
    for path in sorted(list(folder.glob("*.yml")) + list(folder.glob("*.yaml"))):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, yaml.YAMLError):
            continue
        if isinstance(doc, dict):
            docs.append(doc)
    return docs


def infer_legacy_metadata(path, hint):
    hint = (hint or "").strip()
    try:
        with path.open("rb") as handle:
            head = handle.read(4096).decode("utf-8", "replace")
    except OSError:
        head = ""
    lower = hint.lower()
    if head.lstrip().startswith("<Event"):
        channel = re.search(r"<Channel>([^<]+)</Channel>", head)
        if channel:
            source = f"XmlWinEventLog:{channel.group(1)}"
        elif hint and ":" in hint:
            source = hint
        else:
            source = "XmlWinEventLog"
        return "XmlWinEventLog", source
    if lower.startswith("xmlwineventlog:"):
        return "XmlWinEventLog", hint
    if lower.startswith("wineventlog") or hint:
        return hint, hint
    if path.suffix.lower() == ".json":
        return "_json", path.name
    return "attack_data", path.name


def legacy_entries(doc):
    urls = doc.get("dataset") or []
    if isinstance(urls, str):
        urls = [urls]
    hints = doc.get("sourcetypes") or []
    if isinstance(hints, str):
        hints = [hints]
    entries = []
    seen = set()
    for index, raw in enumerate(urls):
        if not isinstance(raw, str) or "/master/" not in raw:
            continue
        local = (ATTACK_DATA / raw.split("/master/", 1)[1]).resolve()
        if not inside_datasets(local) or not local.is_file() or is_lfs_pointer(local):
            continue
        if str(local) in seen:
            continue
        seen.add(str(local))
        if len(hints) == 1:
            hint = hints[0]
        elif len(hints) == len(urls):
            hint = hints[index]
        else:
            hint = hints[0] if hints else ""
        sourcetype, source = infer_legacy_metadata(local, hint)
        entries.append(
            {
                "name": local.stem,
                "path": str(local),
                "sourcetype": sourcetype,
                "source": source,
            }
        )
    return entries


def make_replay_runner(rel):
    def runner(job):
        token = ensure_splunk_ready()
        env = os.environ.copy()
        env.update(
            {
                "SPLUNK_HOST": SPLUNK_HOST,
                "SPLUNK_HEC_TOKEN": token,
                "SPLUNK_USERNAME": SPLUNK_USER,
                "SPLUNK_PASSWORD": SPLUNK_PASSWORD,
                "SPLUNK_PORT": str(SPLUNK_PORT),
                "SPLUNK_VERIFY_SSL": "false",
            }
        )
        python = Path(sys.executable)

        def replay_cmd(path):
            return [str(python), str(REPLAY_PY), str(path), "--index-override", INDEX]

        folder = DATASETS_DIR / rel
        docs = load_yml_docs(folder)
        new_style = any(doc.get("datasets") for doc in docs)
        if new_style:
            run_command(job, replay_cmd(f"datasets/{rel}"), cwd=ATTACK_DATA, env=env)

        temps = []
        try:
            for doc in docs:
                if doc.get("datasets") or not doc.get("dataset"):
                    continue
                entries = legacy_entries(doc)
                if not entries:
                    job.log("Legacy YAML references files that are not available locally; skipped.")
                    continue
                payload = {"id": str(doc.get("id") or uuid.uuid4()), "datasets": entries}
                handle = tempfile.NamedTemporaryFile(
                    "w", suffix=".yml", dir=tempfile_dir(), delete=False, encoding="utf-8"
                )
                with handle:
                    yaml.safe_dump(payload, handle)
                temps.append(handle.name)
                job.log(
                    f"Legacy YAML format: mapped {len(entries)} local file(s) "
                    f"to host {payload['id']}."
                )
                run_command(job, replay_cmd(handle.name), cwd=ATTACK_DATA, env=env)
        finally:
            for path in temps:
                try:
                    os.unlink(path)
                except OSError:
                    pass

        if not new_style and not temps:
            raise RuntimeError(
                "No replayable data files found. The dataset YAML has no usable file "
                "references; download the folder first or pick another dataset."
            )
        job.log("")
        job.log("Sent. Splunk can take 30-60 seconds to index the new events.")
        job.log("Refresh the dashboard, then open a hunt from the Playbook tab.")

    return runner


def make_lab_runner():
    def runner(job):
        file = compose_file()
        if not file.exists():
            raise RuntimeError(f"Docker Compose file not found at {file}.")
        run_command(
            job,
            [
                "docker",
                "compose",
                "--project-directory",
                str(compose_project_dir()),
                "-f",
                str(file),
                "up",
                "-d",
            ],
        )
        wait_for_splunk(job)

    return runner


def merge_props(existing):
    if FIELD_MARKER in existing:
        return existing
    addition = FIELD_PROPS.read_text(encoding="utf-8").strip()
    header = "[XmlWinEventLog]"
    report_line = f"{FIELD_MARKER} = soc_attack_xml_data, soc_attack_xml_eventid, soc_attack_xml_channel, soc_attack_xml_computer"
    lines = existing.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == header:
            lines.insert(index + 1, report_line)
            return "\n".join(lines) + "\n"
    return existing.rstrip() + "\n\n" + addition + "\n"


SOC_COMMENT_PREFIXES = (
    "# --- SOC Lab:",
    "# attack_data replays raw",
    "# XmlWinEventLog sourcetype does not",
    "# HEC-ingested events, so add",
    "# Installed by soc_lab/",
    "# One dynamic extraction covers",
    "# e.g. ProcessName, CommandLine",
)
SOC_FIELD_STANZAS = {
    "soc_attack_xml_data",
    "soc_attack_xml_eventid",
    "soc_attack_xml_channel",
    "soc_attack_xml_computer",
}


def split_stanzas(text):
    return re.split(r"(?m)^(?=\[[^\]\n]+\]\s*$)", text)


def join_blocks(blocks):
    text = "\n\n".join(block.strip("\n") for block in blocks if block.strip())
    return f"{text}\n" if text else ""


def strip_soc_comments(text):
    lines = [
        line
        for line in text.splitlines()
        if not any(line.strip().startswith(prefix) for prefix in SOC_COMMENT_PREFIXES)
    ]
    return "\n".join(lines)


def drop_stanzas(text, names):
    blocks = []
    for block in split_stanzas(text):
        match = re.match(r"^\[([^\]\n]+)\]", block)
        if match and match.group(1).strip() in names:
            continue
        blocks.append(block)
    return join_blocks(blocks)


def drop_empty_stanzas(text):
    blocks = []
    for block in split_stanzas(text):
        lines = [
            line for line in block.splitlines() if line.strip() and not line.strip().startswith("#")
        ]
        if block.lstrip().startswith("[") and len(lines) <= 1:
            continue
        blocks.append(block)
    return join_blocks(blocks)


def strip_field_props(text):
    text = strip_soc_comments(text)
    lines = [line for line in text.splitlines() if "REPORT-soc_attack_xml" not in line]
    return drop_empty_stanzas("\n".join(lines))


def strip_field_transforms(text):
    return drop_stanzas(strip_soc_comments(text), SOC_FIELD_STANZAS)


def read_container_file(path):
    proc = subprocess.run(
        ["docker", "exec", "-u", "root", CONTAINER, "cat", path],
        capture_output=True,
        text=True,
        timeout=15,
    )
    return proc.stdout if proc.returncode == 0 else ""


def write_container_file(job, path, text, backup=False):
    if backup:
        subprocess.run(
            ["docker", "exec", "-u", "root", CONTAINER, "cp", path, path + ".soc_lab.bak"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    with tempfile.NamedTemporaryFile(
        "w", suffix=".conf", dir=tempfile_dir(), delete=False, encoding="utf-8"
    ) as handle:
        handle.write(text)
        temp_path = handle.name
    try:
        run_command(job, ["docker", "cp", temp_path, f"{CONTAINER}:{path}"])
        job.log(f"Wrote {path}")
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass


def remove_container_file(job, path):
    run_command(job, ["docker", "exec", "-u", "root", CONTAINER, "rm", "-f", path])
    job.log(f"Removed {path}")


def chown_container_files(job, *paths):
    run_command(
        job,
        ["docker", "exec", "-u", "root", CONTAINER, "chown", "splunk:splunk", *paths],
    )


def reload_splunk_configs(job):
    for conf in ("props", "transforms"):
        try:
            resp = splunk_request("POST", f"/services/configs/conf-{conf}/_reload", timeout=30)
            job.log(f"Reloaded {conf}: HTTP {resp.status_code}")
        except requests.RequestException as exc:
            raise RuntimeError(
                f"Splunk config was written but Splunk is not reachable to reload: {exc}"
            ) from exc


def make_install_fields_runner():
    def runner(job):
        if not FIELD_PROPS.exists() or not FIELD_TRANSFORMS.exists():
            raise RuntimeError("soc_lab/splunk_config files are missing.")

        job.log("Installing search-time field extraction into Splunk...")
        subprocess.run(
            ["docker", "exec", "-u", "root", CONTAINER, "mkdir", "-p", "/opt/splunk/etc/system/local"],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        )

        existing_props = read_container_file("/opt/splunk/etc/system/local/props.conf")
        merged_props = merge_props(existing_props)
        if merged_props != existing_props:
            write_container_file(
                job, "/opt/splunk/etc/system/local/props.conf", merged_props, backup=True
            )

        existing_transforms = read_container_file("/opt/splunk/etc/system/local/transforms.conf")
        if "soc_attack_xml_eventid" not in existing_transforms:
            merged = existing_transforms.rstrip()
            if merged:
                merged += "\n\n"
            merged += FIELD_TRANSFORMS.read_text(encoding="utf-8").strip() + "\n"
            write_container_file(
                job, "/opt/splunk/etc/system/local/transforms.conf", merged, backup=True
            )

        chown_container_files(
            job,
            "/opt/splunk/etc/system/local/props.conf",
            "/opt/splunk/etc/system/local/transforms.conf",
        )
        reload_splunk_configs(job)

        time.sleep(1)
        job.log("Verifying...")
        probe = splunk_search(
            f"index={INDEX} sourcetype=XmlWinEventLog | head 1 | table EventCode",
            earliest="0",
            limit=1,
        )
        if probe["rows"] and "EventCode" in probe["rows"][0]:
            job.log("Field extraction is active. Windows event fields now work in Splunk Web.")
        else:
            job.log(
                "Fields were installed but could not be verified yet (index may be empty). "
                "Re-run status after indexing data."
            )

    return runner


def make_uninstall_fields_runner():
    def runner(job):
        props_path = "/opt/splunk/etc/system/local/props.conf"
        transforms_path = "/opt/splunk/etc/system/local/transforms.conf"
        existing_props = read_container_file(props_path)
        existing_transforms = read_container_file(transforms_path)
        new_props = strip_field_props(existing_props)
        new_transforms = strip_field_transforms(existing_transforms)
        if new_props == existing_props and new_transforms == existing_transforms:
            job.log("SOC Lab field extraction is not installed.")
            return

        job.log("Removing SOC Lab field extraction...")
        if new_props.strip():
            write_container_file(job, props_path, new_props)
        else:
            remove_container_file(job, props_path)
        if new_transforms.strip():
            write_container_file(job, transforms_path, new_transforms)
        else:
            remove_container_file(job, transforms_path)

        existing = [
            path for path in (props_path, transforms_path) if read_container_file(path).strip()
        ]
        if existing:
            chown_container_files(job, *existing)
        reload_splunk_configs(job)
        job.log("Removed. Reinstall from the dashboard when you need Windows fields again.")

    return runner


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #


class Handler(BaseHTTPRequestHandler):
    server_version = "SOCLab/1.0"

    def log_message(self, fmt, *args):  # keep the console readable
        pass

    def _send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path):
        path = Path(path)
        if not path.is_file():
            self._send_json({"error": "Not found"}, 404)
            return
        content_types = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".svg": "image/svg+xml",
            ".md": "text/plain; charset=utf-8",
        }
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_types.get(path.suffix, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > 1_000_000:
            raise ValueError("Request body too large.")
        if not length:
            return {}
        try:
            payload = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError(f"Invalid JSON body: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError("JSON body must be an object.")
        return payload

    def do_GET(self):
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/":
                self._send_file(UI_DIR / "index.html")
            elif parsed.path.startswith("/static/"):
                rel = parsed.path[len("/static/") :]
                target = (UI_DIR / rel).resolve()
                if UI_DIR.resolve() not in target.parents:
                    self._send_json({"error": "Not found"}, 404)
                else:
                    self._send_file(target)
            elif parsed.path == "/api/status":
                self._send_json(get_status())
            elif parsed.path == "/api/datasets":
                force = parse_qs(parsed.query).get("refresh", ["0"])[0] == "1"
                scan = get_scan(force=force)
                groups = [public_group(g) for g in scan["groups"]]
                self._send_json(
                    {
                        "total": len(groups),
                        "datasets": groups,
                        "categories": sorted({g["category"] for g in groups}),
                    }
                )
            elif parsed.path == "/api/dataset":
                rel = (parse_qs(parsed.query).get("path") or [""])[0]
                group = get_scan()["by_path"].get(rel)
                if not group:
                    self._send_json({"error": "Dataset folder not found."}, 404)
                    return
                detail = public_group(group)
                detail.update(
                    {
                        "files": group["files"],
                        "yml_files": group["ymls"],
                        "local_files": group["local_files"],
                        "environment": group["environment"],
                        "legacy": group["legacy"],
                    }
                )
                self._send_json(detail)
            elif parsed.path == "/api/recipes":
                recipes = json.loads((APP_DIR / "recipes.json").read_text(encoding="utf-8"))
                for phase in recipes:
                    for recipe in phase.get("recipes", []):
                        recipe["spl"] = recipe["spl"].replace("index=attack_data", f"index={INDEX}")
                self._send_json(recipes)
            elif parsed.path.startswith("/api/guide/"):
                name = parsed.path[len("/api/guide/") :]
                if name not in ("SOC_PRACTICE_GUIDE.md", "SOC_EXERCISE_GUIDE.md"):
                    self._send_json({"error": "Guide not found."}, 404)
                    return
                for base in (APP_DIR / "docs", LAB_ROOT):
                    if (base / name).is_file():
                        self._send_file(base / name)
                        return
                self._send_json({"error": "Guide not found."}, 404)
            elif parsed.path == "/api/jobs":
                with JOBS_LOCK:
                    jobs = [job.snapshot() for job in JOBS.values()]
                self._send_json(sorted(jobs, key=lambda job: job["started"], reverse=True))
            elif parsed.path.startswith("/api/jobs/"):
                job = JOBS.get(parsed.path.rsplit("/", 1)[-1])
                if not job:
                    self._send_json({"error": "Job not found."}, 404)
                else:
                    self._send_json(job.snapshot())
            else:
                self._send_json({"error": "Not found"}, 404)
        except SplunkError as exc:
            self._send_json({"error": str(exc)}, 502)
        except ValueError as exc:
            self._send_json({"error": str(exc)}, 400)
        except Exception as exc:
            self._send_json({"error": f"{type(exc).__name__}: {exc}"}, 500)

    def do_POST(self):
        parsed = urlparse(self.path)
        try:
            payload = self._read_json()
            if parsed.path == "/api/download":
                target = safe_dataset_dir(payload.get("path"))
                rel = target.relative_to(DATASETS_DIR.resolve()).as_posix()
                job = start_job(f"Download {rel}", "download", make_download_runner(rel))
                self._send_json(job.snapshot(), 202)
            elif parsed.path == "/api/replay":
                target = safe_dataset_dir(payload.get("path"))
                rel = target.relative_to(DATASETS_DIR.resolve()).as_posix()
                if not list(target.glob("*.yml")) and not list(target.glob("*.yaml")):
                    raise ValueError("This folder has no dataset YAML to replay.")
                job = start_job(f"Replay {rel}", "replay", make_replay_runner(rel))
                self._send_json(job.snapshot(), 202)
            elif parsed.path == "/api/lab/start":
                if docker_status().get("running"):
                    raise ValueError("Splunk is already running.")
                job = start_job("Start Splunk", "lab", make_lab_runner())
                self._send_json(job.snapshot(), 202)
            elif parsed.path == "/api/repo/clone":
                if DATASETS_DIR.is_dir():
                    raise ValueError("attack_data is already available.")
                job = start_job("Clone attack_data", "repo", make_repo_runner())
                self._send_json(job.snapshot(), 202)
            elif parsed.path == "/api/install-fields":
                job = start_job("Install Windows field extraction", "setup", make_install_fields_runner())
                self._send_json(job.snapshot(), 202)
            elif parsed.path == "/api/uninstall-fields":
                job = start_job("Remove Windows field extraction", "setup", make_uninstall_fields_runner())
                self._send_json(job.snapshot(), 202)
            elif parsed.path == "/api/dataset/delete-replay":
                rel = str(payload.get("path") or "").strip()
                group = get_scan()["by_path"].get(rel)
                if not group:
                    raise ValueError("Dataset folder not found.")
                if not group["host_list"]:
                    raise ValueError("This dataset has no host id, so its events cannot be scoped.")
                job = start_job(f"Delete replayed events · {rel}", "delete", make_delete_replay_runner(group["host_list"]))
                self._send_json(job.snapshot(), 202)
            elif parsed.path == "/api/dataset/delete-download":
                target = safe_dataset_dir(payload.get("path"))
                rel = target.relative_to(DATASETS_DIR.resolve()).as_posix()
                job = start_job(f"Delete downloaded files · {rel}", "delete", make_delete_download_runner(rel))
                self._send_json(job.snapshot(), 202)
            elif parsed.path == "/api/lab/delete-replay":
                job = start_job("Delete all replayed events", "delete", make_delete_all_replay_runner())
                self._send_json(job.snapshot(), 202)
            elif parsed.path == "/api/repo/remove":
                job = start_job("Remove local attack_data checkout", "delete", make_remove_repo_runner())
                self._send_json(job.snapshot(), 202)
            elif parsed.path == "/api/search":
                spl = payload.get("q") or ""
                if len(spl) > 20000:
                    raise ValueError("Search is too long.")
                range_name = payload.get("range") or "24h"
                if range_name not in RANGES:
                    raise ValueError("Unknown time range.")
                try:
                    limit = int(payload.get("limit") or 200)
                except (TypeError, ValueError):
                    limit = 200
                earliest, latest = RANGES[range_name]
                self._send_json(splunk_search(spl, earliest, latest, max(1, min(limit, 500))))
            else:
                self._send_json({"error": "Not found"}, 404)
        except SplunkError as exc:
            self._send_json({"error": str(exc)}, 502)
        except ValueError as exc:
            self._send_json({"error": str(exc)}, 400)
        except Exception as exc:
            self._send_json({"error": f"{type(exc).__name__}: {exc}"}, 500)


def main():
    parser = argparse.ArgumentParser(description="Local web UI for the Splunk attack_data SOC lab.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    if not DATASETS_DIR.is_dir():
        print(
            f"attack_data not found at {ATTACK_DATA}. Start the UI and clone it from the "
            "dashboard, or set ATTACK_DATA_DIR."
        )

    try:
        server = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            sys.exit(
                f"Port {args.port} is already in use. SOC Lab is probably already running at\n"
                f"  http://{args.host}:{args.port}\n"
                "Open that URL, or stop the old process, or use another port:\n"
                f"  ./.venv/bin/python app.py --port {args.port + 1}"
            )
        raise
    url = f"http://{args.host}:{args.port}"
    print(f"SOC Lab UI: {url}")
    print(f"attack_data: {ATTACK_DATA}")
    print(f"Splunk API:  {SPLUNK_URL}")
    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
