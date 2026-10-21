# Vendored code

This demo runs the **real** auditor code. The Python package below is a
byte-for-byte copy of the upstream project, so the detection rules, severities,
line numbers, risk score and JSON report schema are the upstream ones.

| | |
|---|---|
| Source repository | https://github.com/samihathecss/wp-plugin-risk-hardening-auditor |
| Commit | `22453068589881b9d70ace81612f2e08021c7bef` |
| Commit date | 2026-10-16 — *"Initial release: WP Plugin Risk & Hardening Auditor"* |
| Upstream path | `src/wp_plugin_auditor/` |
| Local checkout | `D:\WP Plugin Risk & Hardening Auditor` |
| Package version | 0.1.0 (`pyproject.toml`) |

The upstream repository is **not modified** by this demo. The files are copied
unchanged; only the demo folder inside the portfolio repository was added.

## Files copied

| File | SHA-256 | Why it is needed |
|---|---|---|
| `__init__.py` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Package marker (upstream file is empty). |
| `models.py` | `85051154d03f2d212370d450d04041e96515567dddae40bd0341e97a1092439e` | `Finding` dataclass and `Severity` enum used by every other module. |
| `scanner.py` | `f0afb3c57b49bb69c413911e2cb4a0183f7cd762f3acfd3a24828fad5147f9be` | `scan_php_text()` — the four detection rules (PHP001–PHP004). |
| `file_scanner.py` | `981f28e1cce441b6eb1c7c5be6257f625e84909c75e5068ab3a1926a0a7717fa` | `scan_php_file()` — reads one PHP file as UTF-8 text and applies the 1 MB limit. |
| `scoring.py` | `b4104075b7ceedf4e75098de42635545b8852289c662fdc9446bfddb0e56c08a` | `score_findings()` — the severity weights behind the risk score. |
| `reporting.py` | `62107d8f243ef829d38f4d1d91a1101be7d062ae9d388ae6cb9b45c27135f9cf` | `build_report()` and `report_to_json()` — the report schema (`schema_version` `1.0`). |

## Files deliberately not copied

| Upstream file | Reason |
|---|---|
| `cli.py` | Command-line entry point. It only wires the same functions to `argparse` and writes files to disk; the browser demo calls the functions directly. |
| `directory_scanner.py` | `scan_plugin_directory()` walks a real directory. A browser cannot read a local directory, and the upstream function aborts the whole scan when one file is unreadable. The demo scans file by file with the upstream `scan_php_file()` so that a single bad file is reported as skipped instead of ending the scan. This deviation is stated in the demo's limitations panel. |
| `app.py` (repository root) | Streamlit user interface. It is not part of the package and needs a server. |
| `diagnostic_temp.py`, `get_short_path.py`, `run_test.bat`, `test_output.txt` | Development leftovers in the repository root; not part of the package. |

## How the copy is loaded

`app.js` fetches the six files from this folder (`wp_plugin_auditor/<name>`,
same origin as the demo page), writes them into the Pyodide in-memory
filesystem at `/app/wp_plugin_auditor/` and adds `/app` to `sys.path`. No
remote code is fetched at runtime, and the upstream repository is never
contacted by the demo.

## Updating the copy

```powershell
$src = 'D:\WP Plugin Risk & Hardening Auditor\src\wp_plugin_auditor'
$dst = '.\demos\wp-plugin-auditor\wp_plugin_auditor'
git -C 'D:\WP Plugin Risk & Hardening Auditor' rev-parse HEAD
foreach ($f in @('__init__.py','models.py','scanner.py','file_scanner.py','scoring.py','reporting.py')) {
    Copy-Item -LiteralPath (Join-Path $src $f) -Destination (Join-Path $dst $f) -Force
}
```

After copying, update the commit SHA and the hash table above. The upstream
project has no `LICENSE` file, so no licence text is reproduced here.
