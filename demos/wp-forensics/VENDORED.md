# Vendored Code

This browser demo runs the **real** Python implementation of the
WP Forensics & Recovery Assistant. The package source below is a
byte-for-byte, unmodified copy of the upstream project. Nothing in the
copied files has been edited, refactored, or reimplemented.

## Source

- **Repository:** https://github.com/samihathecss/wp-forensics-recovery-assistant
- **Commit:** `bf82f8839a09d76728e1197f7490254324162afb`
- **Branch:** `main`
- **Commit date:** 2026-10-16
- **Upstream package version:** 0.1.0
- **Upstream license:** no `LICENSE` file was present in the source checkout;
  licensing terms are those of the upstream repository.

## Vendored files

Copied verbatim from the upstream `wp_forensics/` package directory:

| File | Bytes | Why it is needed |
| --- | --- | --- |
| `__init__.py` | 1186 | Package entry point and public API (`inspect_zip`, `safe_extract_zip`, report helpers). |
| `archive.py` | 23686 | `inspect_zip()` — archive safety inspection used by this milestone. |
| `config.py` | 1938 | `ScanConfig` — the limit set applied to every browser scan. |
| `compare.py` | 7361 | Snapshot comparison (`compare_snapshots()`) used by the snapshot comparison milestone. |
| `core_verify.py` | 9209 | WordPress core integrity verification (later milestone). |
| `hashing.py` | 9996 | SHA-256 hashing and symlink safety helpers. |
| `indicators.py` | 25457 | Suspicious indicator rules (scanning milestone). |
| `models.py` | 6762 | Result and finding data models. |
| `report.py` | 24048 | JSON and HTML report generation (reporting milestone). |
| `version.py` | 6917 | WordPress version and locale detection. |

## Deliberately excluded

- `cli.py` and `__main__.py` — command-line entry points, not used in the browser.
- `hashing_header.txt`, `hashing_current_function.txt`, `hashing_tail.txt` —
  stray working files in the upstream package directory, not importable modules.
- `app.py`, `tests/`, `dist/` — Streamlit UI, tests, and build artefacts.

## How the demo loads this code

`app.js` fetches each file from this folder and writes it into the Pyodide
in-memory filesystem at `/app/wp_forensics/`, then imports the package with
`sys.path.insert(0, '/app')`. The code is never fetched from a remote origin at
runtime and is never modified.

## Updating

To move the demo to a newer upstream revision, copy the package files listed
above from the upstream repository at the desired commit, re-verify the
SHA-256 hashes against the source, and update the commit reference in this
file. Do not edit the vendored files themselves — upstream changes must stay
traceable to the upstream repository.
