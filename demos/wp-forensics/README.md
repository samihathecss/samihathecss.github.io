# WP Forensics &amp; Recovery Assistant — browser demo

Live demo: **https://samihathecss.github.io/demos/wp-forensics/**

This page runs the real forensics code in your browser. The Python package in
`wp_forensics/` is a byte-for-byte copy of the upstream project, so the
inspection verdicts, detection indicators, comparison results and report
schema are the upstream ones.

- Upstream project: https://github.com/samihathecss/wp-forensics-recovery-assistant
- Vendored commit: `bf82f8839a09d76728e1197f7490254324162afb` (see [VENDORED.md](VENDORED.md))

## What it does

| Feature | Upstream code used | Faithful? |
|---|---|---|
| Inspect a backup ZIP | `archive.inspect_zip()` | Yes |
| Scan a backup | `archive.safe_extract_zip()` → `indicators.scan_directory()` | Yes |
| JSON and HTML reports | `report.generate_json_report()`, `report.generate_html_report()` | Yes |
| Compare two snapshots | `compare.compare_snapshots()` | Yes |
| WordPress core integrity check | `version.detect_wordpress_info()`, `hashing.hash_directory()`, `core_verify.verify_core()` | **Partial** — see below |

The command-line tool and its Streamlit interface are not reproduced; only
the analysis engine is.

### Core verification is partial

The official WordPress.org checksums are fetched by the **browser**, because
the Python runtime inside the page has no network access. The comparison
itself (hashing, the match/mismatch/missing/unchecked verdicts) is the
upstream code. Only the files listed in the official checksum set for the
detected version and locale are compared — plugins, themes, uploads and
`wp-content` are not checked — so a result without mismatches is not a proof
that the installation is clean. The page states this where the result is
shown.

## Privacy

- Everything happens **in your browser**. There is no upload endpoint and no
  server-side analysis.
- The only network requests are the public **Pyodide 0.26.4** and
  **JSZip 3.10.1** libraries from jsDelivr, the vendored Python modules
  served from this folder, and — for the core check only — a request to
  `api.wordpress.org` that carries **the version and locale and nothing
  else**.
- Uploaded PHP is never executed. It is read as plain text.
- Extracted files and the staged archive are deleted from the in-memory
  filesystem after every run, including failed runs.
- Reports are generated in the browser and saved straight to your device. The
  HTML report is a download only; it is never opened or inserted into the
  page. Evidence from sensitive files (`wp-config.php`, `.env`, `*.pem`,
  `*.key`, `id_rsa`, names containing "credentials", `*.sql`) is redacted.

## Safety limits

| Limit | Value |
|---|---|
| Maximum upload size | 25 MB |
| Maximum uncompressed size | 50 MB |
| Maximum archive entries | 2,000 |
| Maximum files scanned | 1,000 |
| Maximum size per file | 5 MB |
| Maximum compression ratio | 100:1 |

An archive that breaks a limit is rejected before a single entry is extracted.
The upstream `safe_extract_zip()` performs the extraction checks, and the
demo additionally rejects symbolic links that carry ordinary permission bits
(a gap in the upstream `is_symlink()` helper, which is disclosed in the
demo's limitations panel).

## Limitations

- The first load downloads the Pyodide runtime (tens of megabytes) and can
  take around 30 seconds. Large archives can exceed browser memory limits.
- Only ZIP archives you explicitly select can be analysed; the demo cannot
  read a local directory.
- Snapshot comparison needs two ZIP archives; both are read into the
  in-memory filesystem, compared by path and SHA-256 hash, and deleted
  afterwards.
- Findings are indicators with status `suspicious`. None of them is
  confirmed malware, and a clean scan does not prove a site is free of it.
- Core verification is partial and needs network access; see above.

## Files

```
demos/wp-forensics/
├── index.html            # Demo page
├── app.js                # Upload handling, safety gate, scanning, reports
├── README.md             # This file
├── VENDORED.md           # Provenance of the copied Python package
└── wp_forensics/         # Upstream package, copied verbatim
    ├── __init__.py
    ├── config.py
    ├── models.py
    ├── archive.py
    ├── indicators.py
    ├── report.py
    ├── compare.py
    ├── hashing.py
    ├── version.py
    └── core_verify.py
```

## Running locally

No build step. Serve the repository root with any static server:

```bash
python -m http.server 8000
```

Then open `http://localhost:8000/demos/wp-forensics/`.

## Deployment

The demo is a static folder in the portfolio repository
(`samihathecss/samihathecss.github.io`) and is published by GitHub Pages from
the `main` branch. There is no build step, no server and no configuration:
the folder is served as-is at `/demos/wp-forensics/`. Nothing in the demo
depends on the original Python repository at runtime, so that repository can
be updated or archived without breaking this page.
