# WP Plugin Risk &amp; Hardening Auditor — browser demo

Live demo: **https://samihathecss.github.io/demos/wp-plugin-auditor/**

This page runs the real auditor code in your browser. The Python modules in
`wp_plugin_auditor/` are a byte-for-byte copy of the upstream project, so the
detection rules, severities, line numbers, risk score and JSON report schema
are the upstream ones.

- Upstream project: https://github.com/samihathecss/wp-plugin-risk-hardening-auditor
- Vendored commit: `22453068589881b9d70ace81612f2e08021c7bef` (see [VENDORED.md](VENDORED.md))

## What it does

1. You select a plugin **ZIP archive** or one or more **`.php` files**.
2. The archive is checked for unsafe entries *before* anything is read.
3. Every PHP file is read as text and matched by the upstream scanner.
4. Findings, the risk score and a JSON report are shown on the page; the JSON
   report can be downloaded.

The upstream command-line tool scans a directory. A browser cannot read a
local directory, so this demo accepts an archive or a file selection instead
and applies the same limits.

## Detection rules

The upstream scanner matches four case-insensitive regular expressions:

| Rule | Pattern | Severity | Weight |
|---|---|---|---|
| `PHP001` | `eval()` | HIGH | 6 |
| `PHP002` | `unserialize()` | HIGH | 6 |
| `PHP003` | `shell_exec()`, `exec()`, `system()`, `passthru()` | MEDIUM | 3 |
| `PHP004` | `base64_decode()` | MEDIUM | 3 |

Risk score = the sum of the severity weights of all findings
(info 0, low 1, medium 3, high 6, critical 10).

## Privacy

- Everything happens **in your browser**. There is no upload endpoint and no
  server-side analysis.
- The only network requests are the public **Pyodide 0.26.4** and
  **JSZip 3.10.1** libraries from jsDelivr, plus the vendored Python modules
  served from this folder.
- Uploaded PHP is never executed, imported or served. It is read as bytes and
  matched against regular expressions.
- Temporary files in the in-memory filesystem are deleted after every run,
  including failed runs.
- The JSON report contains rule IDs, severities, file paths, line numbers and
  findings — never file contents.

## Safety limits

Enforced before any file is read:

| Limit | Value |
|---|---|
| Maximum upload size | 25 MB |
| Maximum archive entries | 2,000 |
| Maximum expanded size | 20 MB |
| Maximum compression ratio | 100:1 |
| Maximum PHP files scanned | 500 |
| Maximum size per PHP file | 1 MB |

An archive is rejected outright when it contains a path traversal, an
absolute path, a symbolic link, a duplicate entry name, an encrypted entry,
an unsupported compression method, too many entries, too much expanded data
or a compression-ratio bomb. Rejected archives are never extracted.

## Limitations

- The scanner uses **regular-expression heuristics. It is not a PHP parser.**
  It cannot understand strings, comments or obfuscation, so it produces both
  false positives and false negatives.
- A match, or a non-zero risk score, does **not** prove that a vulnerability
  exists. The risk score is a prioritisation aid, not a security metric.
- Where the command-line tool aborts the whole scan when a file is
  unreadable, too large or not valid UTF-8, this demo records that file as
  skipped and continues with the remaining files.
- Plugin metadata checks, network behaviour checks and any analysis outside
  the four regex rules are not part of this demo.
- The first load downloads the Pyodide runtime (tens of megabytes) and can
  take around 30 seconds. Large archives can exceed browser memory limits.

## Files

```
demos/wp-plugin-auditor/
├── index.html            # Demo page
├── app.js                # Upload handling, safety gate, scanning, rendering
├── README.md             # This file
├── VENDORED.md           # Provenance of the copied Python package
└── wp_plugin_auditor/    # Upstream package, copied verbatim
    ├── __init__.py
    ├── models.py
    ├── scanner.py
    ├── file_scanner.py
    ├── scoring.py
    └── reporting.py
```

## Running locally

No build step. Serve the repository root with any static server:

```bash
python -m http.server 8000
```

Then open `http://localhost:8000/demos/wp-plugin-auditor/`.

## Deployment

The demo is a static folder in the portfolio repository
(`samihathecss/samihathecss.github.io`) and is published by GitHub Pages from
the `main` branch. There is no build step, no server and no configuration:
the folder is served as-is at `/demos/wp-plugin-auditor/`. Nothing in the demo
depends on the original Python repository at runtime, so that repository can
be updated or archived without breaking this page.
