#!/usr/bin/env python3
"""Scan the add-ons listed in Addons.ini for malware.

For every active (not commented out) section, each DownloadUrl* file is
downloaded and checked with ClamAV (locally) and VirusTotal (~70 engines).
Sections without a DownloadUrl* that link a GitHub repository get every file of
that repository's latest release scanned instead.
A file counts as infected when ClamAV flags it, or when at least MIN_DETECTIONS
VirusTotal engines flag it.

Files are identified by the SHA-256 of the downloaded bytes, never by name or URL.
ClamAV scans every file on every run. VirusTotal results are remembered per hash in
VT_CACHE, so only new files, and known files that are due for a re-check, cost
VirusTotal requests. Each run spends at most VT_BUDGET requests: new files first,
then the most overdue re-checks. Files not reached yet are reported as Pending.

Outputs:
  * REPORT_INI (AddonsScan.ini) - machine-readable result per section, meant
    to be read by the ReShade setup.
  * ADDONS_INI (Addons.ini) - infected sections are commented out in place.
  * VT_CACHE (VirusTotalCache.json) - VirusTotal results per SHA-256.
  * A Markdown summary in $GITHUB_STEP_SUMMARY when running in GitHub Actions.

Environment variables:
  VT_API_KEY           VirusTotal API key (VirusTotal is skipped if unset)
  GITHUB_TOKEN         GitHub token for the release API (optional, raises rate limits)
  ADDONS_INI           add-on list to scan and edit   (default: Addons.ini)
  REPORT_INI           report file to write           (default: AddonsScan.ini)
  VT_CACHE             VirusTotal result cache        (default: VirusTotalCache.json)
  MIN_DETECTIONS       VirusTotal engines needed to flag a file (default: 2)
  VT_BUDGET            max VirusTotal requests per run (default: 250, free tier = 500/day)
  VT_REQUEST_INTERVAL  seconds between VT requests    (default: 15, free tier = 4/min)
  VT_RECHECK_DAYS      re-check a known file on VT after this many days (default: 7)
  CLAMAV_DB            ClamAV database directory      (default: clamscan's own)
"""

import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time

import requests

ADDONS_INI = os.environ.get("ADDONS_INI", "Addons.ini")
REPORT_INI = os.environ.get("REPORT_INI", "AddonsScan.ini")
VT_CACHE = os.environ.get("VT_CACHE", "VirusTotalCache.json")
MIN_DETECTIONS = int(os.environ.get("MIN_DETECTIONS", "2"))
VT_API_KEY = os.environ.get("VT_API_KEY", "").strip()
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
VT_BUDGET = int(os.environ.get("VT_BUDGET", "250"))
VT_REQUEST_INTERVAL = float(os.environ.get("VT_REQUEST_INTERVAL", "15"))
VT_RECHECK_DAYS = float(os.environ.get("VT_RECHECK_DAYS", "7"))
CLAMAV_DB = os.environ.get("CLAMAV_DB", "")

VT_API = "https://www.virustotal.com/api/v3"
VT_MAX_DIRECT_UPLOAD = 32 * 1024 * 1024
VT_MAX_UPLOAD = 650 * 1024 * 1024
VT_UPLOAD_WAIT = 3 * 60      # before looking up files uploaded in this run once more
VT_FOLLOW_UP = 6 * 3600      # uploads and re-analysis requests are looked up on the next run
CACHE_FORGET_DAYS = 30       # drop cache entries for files not seen for this long
DAY = 86400

SECTION_RE = re.compile(r"^\[(?P<name>[^\]]+)\]\s*$")
COMMENTED_SECTION_RE = re.compile(r"^\s*#\s*\[[^\]]+\]\s*$")
GITHUB_REPO_RE = re.compile(r"^https?://github\.com/(?P<owner>[^/\s]+)/(?P<repo>[^/\s#?]+)")

# Statuses, by severity (a section shows its worst file)
CLEAN, PENDING, UNKNOWN, INFECTED = "Clean", "Pending", "Unknown", "Infected"
NO_DOWNLOAD = "NoDownload"
SEVERITY = {NO_DOWNLOAD: -1, CLEAN: 0, PENDING: 1, UNKNOWN: 2, INFECTED: 3}


def log(msg):
    print(msg, flush=True)


def worst(*statuses):
    return max(statuses, key=SEVERITY.get)


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


# --- GitHub releases ------------------------------------------------------------

def github_get(url, **params):
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return requests.get(url, headers=headers, params=params, timeout=60)


def latest_release(repository_url):
    """Return (tag, html_url, [(name, download_url)]), or None if the repo has no release."""
    m = GITHUB_REPO_RE.match(repository_url)
    if not m:
        return None
    owner, repo = m.group("owner"), m.group("repo").removesuffix(".git")
    r = github_get(f"https://api.github.com/repos/{owner}/{repo}/releases/latest")
    if r.status_code == 404:
        return None
    r.raise_for_status()
    release = r.json()
    assets = []
    page = 1
    while True:  # the release object lists assets incompletely for big releases, so page through them
        r = github_get(f"https://api.github.com/repos/{owner}/{repo}/releases/{release['id']}/assets",
                       per_page=100, page=page)
        r.raise_for_status()
        batch = r.json()
        assets += [(a["name"], a["browser_download_url"]) for a in batch]
        if len(batch) < 100:
            break
        page += 1
    return release["tag_name"], release["html_url"], assets


def section_files(section):
    """Resolve the files a section offers: its DownloadUrl* entries, or else its latest GitHub release.

    Returns a list of (label, url, is_release_file) and fills section["release"] / section["error"].
    """
    values = section["values"]
    items = [(k, v, False) for k, v in values.items() if k.startswith("DownloadUrl") and v]
    if items or not values.get("RepositoryUrl"):
        return items
    try:
        release = latest_release(values["RepositoryUrl"])
    except Exception as e:
        section["error"] = f"could not read latest release: {e}"
        log(f"  {section['error']}")
        return []
    if release is None:
        return []
    tag, html_url, assets = release
    section["release"] = {"tag": tag, "url": html_url, "files": len(assets)}
    log(f"[{section['name']}] latest release {tag}: {len(assets)} files")
    return [(f"ReleaseFile{i}", url, True) for i, (_, url) in enumerate(assets, 1)]


# --- Downloading --------------------------------------------------------------

def download(url, dest_dir, index):
    name = re.sub(r"[^A-Za-z0-9._-]", "_", url.rsplit("/", 1)[-1]) or "file"
    path = os.path.join(dest_dir, f"{index:04d}_{name}")
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
    """Return {path: signature}, or None if ClamAV could not run."""
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

class QuotaExhausted(Exception):
    pass


class VirusTotal:
    def __init__(self, key):
        self.session = requests.Session()
        self.session.headers["x-apikey"] = key
        self.last_request = 0.0
        self.used = 0

    def request(self, method, url, **kwargs):
        for attempt in range(2):
            if self.used >= VT_BUDGET:
                raise QuotaExhausted(f"run budget of {VT_BUDGET} requests used up")
            wait = self.last_request + VT_REQUEST_INTERVAL - time.time()
            if wait > 0:
                time.sleep(wait)
            self.last_request = time.time()
            self.used += 1
            r = self.session.request(method, url, timeout=300, **kwargs)
            if r.status_code != 429:
                return r
            if attempt == 0:  # per-minute limit: wait and retry once
                log("VirusTotal: rate limited, waiting 60s")
                time.sleep(60)
        raise QuotaExhausted("VirusTotal quota exceeded")

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

    def reanalyse(self, sha256):
        self.request("POST", f"{VT_API}/files/{sha256}/analyse").raise_for_status()


def vt_check(vt, sha, path, cache, now, uploaded):
    """Look up one file on VirusTotal and update its cache entry.

    Never waits for an analysis: uploads and re-analysis requests are picked up
    by a later lookup (VT_FOLLOW_UP), so each file costs 1-2 requests.
    """
    entry = cache.setdefault(sha, {})
    report = vt.file_report(sha)
    if report is None or not report.get("last_analysis_results"):
        if "uploaded" not in entry:
            if os.path.getsize(path) > VT_MAX_UPLOAD:
                raise ValueError("file too large for VirusTotal")
            log("  unknown to VirusTotal, uploading")
            vt.upload(path)
            entry["uploaded"] = time.time()
            uploaded.append(sha)
        entry["due"] = now + VT_FOLLOW_UP
        return
    analysed = report.get("last_analysis_date", 0)
    entry.pop("uploaded", None)
    entry["malicious"] = sorted(engine for engine, res in report["last_analysis_results"].items()
                                if res.get("category") == "malicious")
    entry["analysed"] = analysed
    entry["checked"] = now
    if now - analysed > VT_RECHECK_DAYS * DAY:
        # VirusTotal's verdict is old; ask for a fresh one and read it on the next run
        log(f"  last analysis {(now - analysed) / DAY:.0f} days old, requesting re-analysis")
        vt.reanalyse(sha)
        entry["due"] = now + VT_FOLLOW_UP
    else:
        entry["due"] = now + VT_RECHECK_DAYS * DAY - VT_FOLLOW_UP


def run_virustotal(files, cache, now):
    """Spend up to VT_BUDGET requests on new files first, then on the most overdue re-checks."""
    paths = {}
    for info in files.values():
        if info["sha256"]:
            paths.setdefault(info["sha256"], info["path"])
    new = [sha for sha in paths if sha not in cache]
    due = sorted((sha for sha in paths if sha in cache and cache[sha].get("due", 0) <= now),
                 key=lambda sha: cache[sha].get("due", 0))
    log(f"VirusTotal: {len(paths)} distinct files, {len(new)} new, {len(due)} due for a re-check")
    vt = VirusTotal(VT_API_KEY)
    uploaded, errors, done = [], {}, 0
    try:
        for sha in new + due:
            log(f"VirusTotal: {sha} ({os.path.basename(paths[sha])})")
            try:
                vt_check(vt, sha, paths[sha], cache, now, uploaded)
                done += 1
            except QuotaExhausted:
                raise
            except Exception as e:
                log(f"  failed: {e}")
                errors[sha] = str(e)
        # Uploads are usually analysed within minutes, so try to get their result in this run
        if uploaded:
            time.sleep(max(0, cache[uploaded[-1]]["uploaded"] + VT_UPLOAD_WAIT - time.time()))
            for sha in uploaded:
                try:
                    vt_check(vt, sha, paths[sha], cache, now, [])
                except QuotaExhausted:
                    raise
                except Exception as e:
                    log(f"  {sha}: {e}")
    except QuotaExhausted as e:
        log(f"VirusTotal: stopping, {e}")
    for sha in paths:
        if sha in cache:
            cache[sha]["seen"] = now
    stats = {"requests": vt.used, "checked": done, "new": len(new), "due": len(due)}
    return errors, stats


def load_cache():
    try:
        with open(VT_CACHE, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_cache(cache, now):
    cache = {sha: e for sha, e in cache.items() if now - e.get("seen", now) < CACHE_FORGET_DAYS * DAY}
    with open(VT_CACHE, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cache, f, indent=1, sort_keys=True)
        f.write("\n")


def vt_verdict(sha, cache, errors):
    """(status, detections) according to VirusTotal."""
    if not VT_API_KEY or not sha:
        return UNKNOWN, None
    entry = cache.get(sha, {})
    if "malicious" in entry:
        n = len(entry["malicious"])
        return (INFECTED if n >= MIN_DETECTIONS else CLEAN), n
    return (UNKNOWN if sha in errors else PENDING), None


# --- Main ---------------------------------------------------------------------

def main():
    with open(ADDONS_INI, encoding="utf-8") as f:
        lines = f.readlines()
    sections = parse_sections(lines)
    log(f"{len(sections)} active sections in {ADDONS_INI}")
    if not VT_API_KEY:
        log("VT_API_KEY not set, VirusTotal is skipped")

    now = time.time()
    cache = load_cache()
    vt_errors, vt_stats = {}, None

    with tempfile.TemporaryDirectory() as tmp:
        # Download every file once, even if several sections share a URL
        files = {}  # url -> dict(path, sha256, error, clamav)
        for section in sections:
            section["items"] = section_files(section)
            for _, url, _ in section["items"]:
                if url in files:
                    continue
                try:
                    path, sha = download(url, tmp, len(files))
                    files[url] = {"path": path, "sha256": sha, "error": None, "clamav": None}
                except Exception as e:
                    log(f"Downloading {url} failed: {e}")
                    files[url] = {"path": None, "sha256": "", "error": f"download failed: {e}", "clamav": None}
        log(f"Downloaded {sum(1 for i in files.values() if i['path'])} of {len(files)} files")

        log("Running ClamAV")
        clam = clamav_scan(tmp)
        if clam is not None:
            for info in files.values():
                if info["path"] is None:
                    continue
                # clamscan reports archive members as "file.zip" too, so match by prefix
                hits = [sig for p, sig in clam.items() if p == info["path"] or p.startswith(info["path"] + "/")]
                info["clamav"] = hits[0] if hits else "OK"

        if VT_API_KEY:
            vt_errors, vt_stats = run_virustotal(files, cache, now)
            save_cache(cache, now)

    # Evaluate each section: the worst file decides the section status
    today = datetime.date.today().isoformat()
    report = ["; Generated by .github/workflows/addon-scan.yml - do not edit by hand.\n",
              f"; Status: {INFECTED} when either scanner says {INFECTED}, {UNKNOWN} when no scanner "
              f"could check it, {NO_DOWNLOAD} when there is nothing to download, otherwise {CLEAN}.\n",
              f"; ClamAV / VirusTotal: what each scanner says on its own ({CLEAN} | {INFECTED} | "
              f"{PENDING} = not checked yet | {UNKNOWN} = could not be checked).\n",
              f"; VirusTotal counts as {INFECTED} when >= {MIN_DETECTIONS} of its engines flag a file.\n",
              "; Sections without DownloadUrl entries are checked through all files of their latest GitHub\n",
              "; release; only files that are not Clean are listed for those.\n"]
    flagged = []
    summary = []
    for section in sections:
        status = clam_section = vt_section = NO_DOWNLOAD
        vt_max, vt_done, total = 0, 0, 0
        entries = []
        worst_engines = []
        for key, url, is_release in section["items"]:
            info = files[url]
            sha = info["sha256"]
            clam_status = (UNKNOWN if info["clamav"] is None else
                           CLEAN if info["clamav"] == "OK" else INFECTED)
            vt_status, vt_count = vt_verdict(sha, cache, vt_errors)
            engines = sorted(set(cache.get(sha, {}).get("malicious", []) if VT_API_KEY else [])
                             | ({"ClamAV"} if clam_status == INFECTED else set()))
            if INFECTED in (clam_status, vt_status):
                file_status = INFECTED
            elif clam_status in (UNKNOWN,) and vt_status in (UNKNOWN, PENDING):
                file_status = UNKNOWN
            else:
                file_status = CLEAN
            total += 1
            status = worst(status, file_status)
            clam_section = worst(clam_section, clam_status)
            vt_section = worst(vt_section, vt_status)
            vt_max = max(vt_max, vt_count or 0)
            vt_done += vt_count is not None
            if len(engines) > len(worst_engines):
                worst_engines = engines
            if is_release and file_status == CLEAN and not info["error"]:
                continue
            entries += [f"{key}={url}\n",
                        f"{key}.Status={file_status}\n",
                        f"{key}.Sha256={sha}\n",
                        f"{key}.ClamAV={clam_status}\n"]
            if clam_status == INFECTED:
                entries.append(f"{key}.ClamAV.Signature={info['clamav']}\n")
            entries.append(f"{key}.VirusTotal={vt_status}\n")
            if vt_count is not None:
                entries.append(f"{key}.VirusTotal.Detections={vt_count}\n")
            entries.append(f"{key}.Engines={','.join(engines)}\n")
            error = info["error"] or vt_errors.get(sha)
            if error:
                entries.append(f"{key}.Error={error}\n")

        if section.get("error"):
            status = clam_section = vt_section = worst(status, UNKNOWN)
        name = section["values"].get("PackageName", "")
        head = [f"[{section['name']}]\n", f"PackageName={name}\n", f"Status={status}\n",
                f"ClamAV={clam_section}\n", f"VirusTotal={vt_section}\n"]
        if "release" in section:
            head += [f"Release={section['release']['tag']}\n", f"ReleaseUrl={section['release']['url']}\n",
                     f"ReleaseFiles={section['release']['files']}\n"]
        if section.get("error"):
            head.append(f"Error={section['error']}\n")
        report += ["\n"] + head + entries

        if vt_section in (CLEAN, INFECTED):
            vt_cell = f"{vt_section} ({vt_max})"
        elif vt_section == PENDING:
            vt_cell = f"{PENDING} ({vt_done}/{total} checked)"
        else:
            vt_cell = vt_section
        summary.append((section["name"], name, status, clam_section, vt_cell, worst_engines))
        if status == INFECTED:
            section["reason"] = f"flagged by {', '.join(worst_engines)}"
            flagged.append(section)

    with open(REPORT_INI, "w", encoding="utf-8", newline="\n") as f:
        f.writelines(report)
    log(f"Wrote {REPORT_INI}")

    if flagged:
        with open(ADDONS_INI, "w", encoding="utf-8", newline="") as f:
            f.writelines(comment_out_sections(lines, flagged, today))
        log(f"Commented out {len(flagged)} section(s) in {ADDONS_INI}")

    counts = {s: sum(1 for x in summary if x[2] == s) for s in SEVERITY}
    md = [f"## Add-on virus scan ({today})\n\n",
          f"{counts[CLEAN]} clean, {counts[UNKNOWN]} unknown, {counts[INFECTED]} infected, "
          f"{counts[NO_DOWNLOAD]} without download "
          f"(infected = ClamAV detection or >= {MIN_DETECTIONS} VirusTotal engines)\n\n"]
    if vt_stats:
        md.append(f"VirusTotal: {vt_stats['requests']} of {VT_BUDGET} requests used, "
                  f"{vt_stats['checked']} files checked ({vt_stats['new']} new, "
                  f"{vt_stats['due']} due for a re-check)\n\n")
    md.append("| Section | Package | Status | ClamAV | VirusTotal | Engines |\n|---|---|---|---|---|---|\n")
    md += [f"| {sec} | {name} | {status} | {clam} | {vt_cell} | {', '.join(eng)} |\n"
           for sec, name, status, clam, vt_cell, eng in summary]
    log("".join(md))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.writelines(md)
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            f.write(f"infected={counts[INFECTED]}\n")


if __name__ == "__main__":
    sys.exit(main())
