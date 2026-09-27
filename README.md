# hello-world
Just a testing Repository to test **Github** features.

I'm CeeJay.dk and I write shaders.

## Add-on virus scan (proof of concept)

`.github/workflows/addon-scan.yml` runs daily, on demand and whenever `Addons.ini` changes, and scans every active add-on in `Addons.ini`
(a test copy of [crosire/reshade-shaders `list` branch](https://github.com/crosire/reshade-shaders/blob/list/Addons.ini))
with ClamAV and VirusTotal. Scheduled and manual runs first refresh `Addons.ini` from crosire's list. A file counts as infected when ClamAV flags it, or when 2 or more VirusTotal engines flag it.

- `AddonsScan.ini` – machine-readable result per section (`Status=Clean|Infected|Unknown`) for the setup to read.
- `Addons.ini` – infected sections are commented out automatically.
- If anything is infected the run fails, which makes GitHub email you.

Setup: add a free VirusTotal API key as the repository secret `VT_API_KEY`
(Settings → Secrets and variables → Actions).
