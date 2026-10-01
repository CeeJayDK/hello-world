# hello-world
Just a testing Repository to test **Github** features.

I'm CeeJay.dk and I write shaders.

## Add-on virus scan (proof of concept)

`.github/workflows/addon-scan.yml` runs daily, on demand and whenever `Addons.ini` changes, and scans every active add-on in `Addons.ini`
(a test copy of [crosire/reshade-shaders `list` branch](https://github.com/crosire/reshade-shaders/blob/list/Addons.ini))
with ClamAV and VirusTotal. Scheduled and manual runs first refresh `Addons.ini` from crosire's list. A file counts as infected when ClamAV flags it, or when 2 or more VirusTotal engines flag it.
Entries that only link a GitHub repository are checked through every file of that repository's latest release.

Files are identified by the SHA-256 of their content, never by name or URL. ClamAV scans everything on every run;
VirusTotal is only asked about new files and, about once a week, re-checks known ones (at most 250 requests per run,
new files first). Files it has not reached yet show as `Pending`.

- `AddonsScan.ini` – machine-readable result per section (`Status=Clean|Infected|Unknown|NoDownload`) for the setup to read.
- `Addons.ini` – infected sections are commented out automatically.
- `VirusTotalCache.json` – remembered VirusTotal results per file hash.
- If anything is infected the run fails, which makes GitHub email you.

Setup: add a free VirusTotal API key as the repository secret `VT_API_KEY`
(Settings → Secrets and variables → Actions).
