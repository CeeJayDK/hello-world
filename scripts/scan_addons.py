#!/usr/bin/env python3
"""Scan the add-ons listed in Addons.ini for malware.

For every active (not commented out) section, each DownloadUrl* file is
downloaded and checked with ClamAV (locally) and VirusTotal (~70 engines).
A file counts as infected when at least MIN_DETECTIONS distinct engines flag it.

Outputs:
  * REPORT_INI (AddonsScan.ini) - machine-readable result per section, meant
    to be read by the ReShade setup.
  * ADDONS_INI (Addons.ini) - infected sections are commented out in place.
  * A Markdown summary in $GITHUB_STEP_SUMMARY when running in GitHub Actions.

Environment variables:
  VT_API_KEY           VirusTotal API key (VirusTotal is skipped if unset)
  ADDONS_INI           add-on list to scan and edit   (default: Addons.ini)
  REPORT_INI           report file to write           (default: AddonsScan.ini)
  MIN_DETECTIONS       engines needed to flag a file  (default: 2)
  VT_REQUEST_INTERVAL  seconds between VT requests    (default: 15, free tier = 4/min)
  VT_REANALYSE_DAYS    re-scan on VT if its last analysis is older (default: 7)
  CLAMAV_DB            ClamAV database directory      (default: clamscan's own)
"""

import datetime
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import time

import requests

ADDONS_INI = os.environ.get("ADDONS_INI", "Addons.ini")
REPORT_INI = os.environ.get("REPORT_INI", "AddonsScan.ini")
MIN_DETECTIONS = int(os.environ.get("MIN_DETECTIONS", "2"))
VT_API_KEY = os.environ.get("VT_API_KEY", "").strip()
VT_REQUEST_INTERVAL = float(os.environ.get("VT_REQUEST_INTERVAL", "15"))
VT_REANALYSE_DAYS = float(os.environ.get("VT_REANALYSE_DAYS", "7"))
CLAMAV_DB = os.environ.get("CLAMAV_DB", "")

VT_API = "https://www.virustotal.com/api/v3"
VT_MAX_DIRECT_UPLOAD = 32 * 1024 * 1024
VT_ANALYSIS_TIMEOUT = 20 * 60

SECTION_RE = re.compile(r"^\[(?P<name>[^\]]+)\]\s*$")
COMMENTED_SECTION_RE = re.compile(r"^\s*#\s*\[[^\]]+\]\s*$")

# Section status, worst last
CLEAN, UNKNOWN, INFECTED = "Clean", "Unknown", "Infected"
SEVERITY = {CLEAN: 0, UNKNOWN: 1, INFECTED: 2}


def log(msg):
    print(msg, flush=True)


# --- Addons.ini parsing ------------------------------------------------------

def parse_sections(lines):
    """Return active sections as dicts with name, header line index and key/values."""
    sections = []
    current = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith(";"):
            continue
        m = SECTION_RE.match(stripped)
        if m:
            current = {"name": m.group("name"), "line": i, "values": {}}
            sections.append(current)
        elif current is not None and "=" in stripped:
            key, value = stripped.split("=", 1)
            current["values"][key.strip()] = value.strip()
    return sections


def section_end(lines, start):
    """Index one past the last line belonging to the section whose header is at `start`."""
    end = start + 1
    while end < len(lines):
        stripped = lines[end].strip()
        if SECTION_RE.match(stripped) or COMMENTED_SECTION_RE.match(stripped):
            break
        end += 1
    # Leave trailing blank lines outside the section
    while end > start + 1 and not lines[end - 1].strip():
        end -= 1
    return end


def comment_out_sections(lines, flagged, today):
    """Comment out flagged sections (name -> reason). Works bottom-up so indices stay valid."""
    for section in sorted(flagged, key=lambda s: s["line"], reverse=True):
        start = section["line"]
        end = section_end(lines, start)
        body = ["# " + l if l.strip() else l for l in lines[start:end]]
        marker = f"# Disabled by virus scan on {today}: {section['reason']}\n"
        lines[start:end] = [marker] + body
    return lines


# --- Downloading --------------------------------------------------------------

def download(url, dest_dir, index):
    name = re.sub(r"[^A-Za-z0-9._-]", "_", url.rsplit("/", 1)[-1]) or "file"
    path = os.path.join(dest_dir, f"{index:03d}_{name}")
    sha = hashlib.sha256()
    with requests.get(url, stream=True, timeout=120, allow_redirects=True) as r:
        r.raise_for_status()
        with open(path, "wb") as f:
            for chunk in r.iter_content(1 << 16):
                f.write(chunk)
                sha.update(chunk)
    return path, sha.hexdigest()


# --- ClamAV -------------------------------------------------------------------

def clamav_scan(directory):
    """Return {path: signature or None}, or None if ClamAV could not run."""
    cmd = ["clamscan", "--recursive", "--no-summary", "--infected",
           "--scan-archive=yes", directory]
    if CLAMAV_DB:
        cmd.insert(1, f"--database={CLAMAV_DB}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        log("ClamAV: clamscan not found, skipping")
        return None
    if proc.returncode not in (0, 1):  # 0 = clean, 1 = virus found, 2 = error
        log(f"ClamAV: error (exit {proc.returncode}): {proc.stderr.strip()}")
        return None
    found = {}
    for line in proc.stdout.splitlines():
        if line.endswith(" FOUND"):
            path, sig = line[:-len(" FOUND")].rsplit(": ", 1)
            found[path] = sig
    return found


# --- VirusTotal ---------------------------------------------------------------

class VirusTotal:
    def __init__(self, key):
        self.session = requests.Session()
        self.session.headers["x-apikey"] = key
        self.last_request = 0.0

    def request(self, method, url, **kwargs):
        for attempt in range(5):
            wait = self.last_request + VT_REQUEST_INTERVAL - time.time()
            if wait > 0:
                time.sleep(wait)
            self.last_request = time.time()
            r = self.session.request(method, url, timeout=300, **kwargs)
            if r.status_code == 429:  # quota exceeded, back off
                log("VirusTotal: rate limited, waiting 60s")
                time.sleep(60)
                continue
            return r
        r.raise_for_status()
        return r

    def file_report(self, sha256):
        r = self.request("GET", f"{VT_API}/files/{sha256}")
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()["data"]["attributes"]

    def upload(self, path):
        url = f"{VT_API}/files"
        if os.path.getsize(path) > VT_MAX_DIRECT_UPLOAD:
            r = self.request("GET", f"{VT_API}/files/upload_url")
            r.raise_for_status()
            url = r.json()["data"]
        with open(path, "rb") as f:
            r = self.request("POST", url, files={"file": (os.path.basename(path), f)})
        r.raise_for_status()
        return r.json()["data"]["id"]

    def reanalyse(self, sha256):
        r = self.request("POST", f"{VT_API}/files/{sha256}/analyse")
        r.raise_for_status()
        return r.json()["data"]["id"]

    def wait_for_analysis(self, analysis_id):
        deadline = time.time() + VT_ANALYSIS_TIMEOUT
        while time.time() < deadline:
            r = self.request("GET", f"{VT_API}/analyses/{analysis_id}")
            r.raise_for_status()
            attrs = r.json()["data"]["attributes"]
            if attrs.get("status") == "completed":
                return attrs["results"]
        raise TimeoutError(f"VirusTotal analysis {analysis_id} did not finish in time")

    def scan(self, path, sha256):
        """Return {engine: category} for the file, uploading or re-scanning as needed."""
        report = self.file_report(sha256)
        if report is None:
            log("  VirusTotal: unknown file, uploading")
            return self.wait_for_analysis(self.upload(path))
        age_days = (time.time() - report.get("last_analysis_date", 0)) / 86400
        if age_days > VT_REANALYSE_DAYS:
            log(f"  VirusTotal: last analysis {age_days:.0f} days old, re-scanning")
            return self.wait_for_analysis(self.reanalyse(sha256))
        return report["last_analysis_results"]


def malicious_engines(results):
    return {engine for engine, res in results.items() if res.get("category") == "malicious"}


# --- Main ---------------------------------------------------------------------

def main():
    with open(ADDONS_INI, encoding="utf-8") as f:
        lines = f.readlines()
    sections = parse_sections(lines)
    log(f"{len(sections)} active sections in {ADDONS_INI}")

    vt = VirusTotal(VT_API_KEY) if VT_API_KEY else None
    if vt is None:
        log("VT_API_KEY not set, VirusTotal is skipped")

    with tempfile.TemporaryDirectory() as tmp:
        # Download every file once, even if several sections share a URL
        files = {}  # url -> dict(path, sha256, error, engines)
        for section in sections:
            for key, url in section["values"].items():
                if key.startswith("DownloadUrl") and url and url not in files:
                    log(f"Downloading {url}")
                    try:
                        path, sha = download(url, tmp, len(files))
                        files[url] = {"path": path, "sha256": sha, "error": None,
                                      "engines": set(), "clamav": None, "vt": None}
                    except Exception as e:
                        log(f"  failed: {e}")
                        files[url] = {"path": None, "sha256": "", "error": f"download failed: {e}",
                                      "engines": set(), "clamav": None, "vt": None}

        log("Running ClamAV")
        clam = clamav_scan(tmp)
        for info in files.values():
            if info["path"] is None or clam is None:
                continue
            # clamscan reports archive members as "file.zip" too, so match by prefix
            hits = [sig for p, sig in clam.items() if p == info["path"] or p.startswith(info["path"] + "/")]
            info["clamav"] = hits[0] if hits else "OK"
            if hits:
                info["engines"].add("ClamAV")

        if vt:
            for url, info in files.items():
                if info["path"] is None:
                    continue
                log(f"VirusTotal: {url}")
                try:
                    engines = malicious_engines(vt.scan(info["path"], info["sha256"]))
                    info["vt"] = len(engines)
                    info["engines"] |= engines
                except Exception as e:
                    log(f"  failed: {e}")
                    info["error"] = f"VirusTotal failed: {e}"

    # Evaluate each section: the worst file decides the section status
    today = datetime.date.today().isoformat()
    report = ["; Generated by .github/workflows/addon-scan.yml - do not edit by hand.\n",
              f"; Status: {CLEAN} | {INFECTED} (>= {MIN_DETECTIONS} engines) | "
              f"{UNKNOWN} (could not be fully scanned)\n"]
    flagged = []
    summary = []
    for section in sections:
        status = CLEAN
        entries = []
        worst_engines = set()
        for key, url in section["values"].items():
            if not key.startswith("DownloadUrl") or url not in files:
                continue
            info = files[url]
            if len(info["engines"]) >= MIN_DETECTIONS:
                file_status = INFECTED
            elif info["error"] or info["clamav"] is None or (vt and info["vt"] is None):
                file_status = UNKNOWN
            else:
                file_status = CLEAN
            if SEVERITY[file_status] > SEVERITY[status]:
                status = file_status
            if len(info["engines"]) > len(worst_engines):
                worst_engines = info["engines"]
            entries += [f"{key}={url}\n",
                        f"{key}.Status={file_status}\n",
                        f"{key}.Sha256={info['sha256']}\n",
                        f"{key}.Detections={len(info['engines'])}\n",
                        f"{key}.Engines={','.join(sorted(info['engines']))}\n",
                        f"{key}.ClamAV={info['clamav'] or 'NotScanned'}\n",
                        f"{key}.VirusTotal={'NotScanned' if info['vt'] is None else info['vt']}\n"]
            if info["error"]:
                entries.append(f"{key}.Error={info['error']}\n")

        name = section["values"].get("PackageName", "")
        report += ["\n", f"[{section['name']}]\n", f"PackageName={name}\n", f"Status={status}\n"] + entries
        summary.append((section["name"], name, status, worst_engines))
        if status == INFECTED:
            section["reason"] = (f"{len(worst_engines)} detections "
                                 f"({', '.join(sorted(worst_engines))})")
            flagged.append(section)

    with open(REPORT_INI, "w", encoding="utf-8", newline="\n") as f:
        f.writelines(report)
    log(f"Wrote {REPORT_INI}")

    if flagged:
        with open(ADDONS_INI, "w", encoding="utf-8", newline="") as f:
            f.writelines(comment_out_sections(lines, flagged, today))
        log(f"Commented out {len(flagged)} section(s) in {ADDONS_INI}")

    counts = {s: sum(1 for x in summary if x[2] == s) for s in (CLEAN, UNKNOWN, INFECTED)}
    md = [f"## Add-on virus scan ({today})\n\n",
          f"{counts[CLEAN]} clean, {counts[UNKNOWN]} unknown, {counts[INFECTED]} infected "
          f"(threshold: {MIN_DETECTIONS} engines)\n\n",
          "| Section | Package | Status | Engines |\n|---|---|---|---|\n"]
    md += [f"| {sec} | {name} | {status} | {', '.join(sorted(eng))} |\n"
           for sec, name, status, eng in summary]
    log("".join(md))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.writelines(md)
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            f.write(f"infected={counts[INFECTED]}\n")


if __name__ == "__main__":
    sys.exit(main())
