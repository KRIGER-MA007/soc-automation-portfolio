# Cybersecurity Project Portfolio

A static portfolio built with HTML, CSS and JavaScript. The landing page links to two separate case studies:

1. **SOC Automation Lab** — Wazuh, Sysmon, Shuffle SOAR, VirusTotal and TheHive.
2. **Three Splunk Threat Hunts** — LSASS access, remote account activity and C2-labelled firewall traffic.

## Run locally

```bash
python3 -m http.server 8000
```

Visit `http://localhost:8000`.

## Structure

- `index.html` — portfolio landing page
- `soc-automation.html` — SOC Automation Lab case study
- `threat-hunting.html` — Splunk threat-hunting case study
- `threat-hunting-evidence/` — 19 supporting Day 6 screenshots
- `style.css` — shared responsive dark-glass interface
- `script.js` — reveal effects, terminal animation and accessible image lightbox

## GitHub Pages

The site is designed to deploy directly from the repository root on the `main` branch.

Profile: <https://github.com/KRIGER-MA007>
