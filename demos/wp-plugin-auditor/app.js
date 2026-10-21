/*
 * WP Plugin Risk & Hardening Auditor - browser demo.
 *
 * This demo runs the project's own Python modules (vendored verbatim in
 * ./wp_plugin_auditor) inside Pyodide, so the detection rules, severities,
 * risk score and JSON report schema are the upstream ones.
 *
 * Safety model:
 *   - Nothing is uploaded. There is no upload endpoint; the only outbound
 *     requests are the public Pyodide/JSZip CDN scripts and the vendored
 *     Python modules served from this folder.
 *   - Uploaded PHP is never executed, imported or served. It is read as bytes
 *     and matched against regular expressions by the upstream scanner.
 *   - An archive is checked (traversal, symlinks, duplicates, sizes, ratios)
 *     before a single entry is read.
 *   - Every untrusted string is written with textContent. This file never
 *     uses innerHTML, outerHTML, insertAdjacentHTML or document.write.
 *   - Temporary files in the in-memory filesystem are removed in a finally
 *     block, including when the scan fails.
 */
(function () {
    "use strict";

    // ---------------------------------------------------------------------
    // Configuration
    // ---------------------------------------------------------------------

    const PYODIDE_INDEX_URL = "https://cdn.jsdelivr.net/pyodide/v0.26.4/full/";

    // Vendored upstream modules, copied verbatim from the project.
    const VENDORED_MODULES = [
        "__init__.py",
        "models.py",
        "scanner.py",
        "file_scanner.py",
        "scoring.py",
        "reporting.py"
    ];

    // In-memory filesystem locations used by the demo.
    const PY_PACKAGE_DIR = "/app/wp_plugin_auditor";
    const PY_SCAN_DIR = "/tmp/wp-audit";
    const PY_ARCHIVE_PATH = "/tmp/plugin.zip";
    const PY_LABEL_PATH = "/tmp/wp-audit-label.txt";

    // Safety limits. The file, count and total byte limits are the upstream
    // defaults of scan_php_file() and scan_plugin_directory(); the upload,
    // entry and ratio limits are the demo's own archive guard.
    const LIMITS = {
        maxUploadBytes: 25 * 1024 * 1024,
        maxEntries: 2000,
        maxTotalBytes: 20000000,
        maxRatio: 100,
        maxFiles: 500,
        maxFileBytes: 1000000
    };

    // ---------------------------------------------------------------------
    // DOM references
    // ---------------------------------------------------------------------

    const uploadArea = document.getElementById("upload-area");
    const chooseZipBtn = document.getElementById("choose-zip-btn");
    const choosePhpBtn = document.getElementById("choose-php-btn");
    const zipInput = document.getElementById("zip-input");
    const phpInput = document.getElementById("php-input");
    const fileInfo = document.getElementById("file-info");
    const scanBtn = document.getElementById("scan-btn");
    const clearBtn = document.getElementById("clear-btn");
    const statusBox = document.getElementById("status");
    const resultsSection = document.getElementById("results-section");
    const scanSummary = document.getElementById("scan-summary");
    const findingsBody = document.getElementById("findings-body");
    const skippedBody = document.getElementById("skipped-body");
    const scanNotes = document.getElementById("scan-notes");
    const downloadJsonBtn = document.getElementById("download-json");

    // ---------------------------------------------------------------------
    // State
    // ---------------------------------------------------------------------

    let pyodide = null;
    let packageReady = false;
    let busy = false;
    let zipFile = null;
    let phpFiles = [];
    let reportJson = "";

    // ---------------------------------------------------------------------
    // Small helpers
    // ---------------------------------------------------------------------

    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null) node.textContent = String(text);
        return node;
    }

    function badge(text, className) {
        return el("span", "badge " + (className || "neutral"), text);
    }

    function severityClass(severity) {
        switch (String(severity || "").toUpperCase()) {
            case "CRITICAL": return "critical";
            case "HIGH": return "unsafe";
            case "MEDIUM": return "warn";
            case "LOW": return "info";
            default: return "neutral";
        }
    }

    function showStatus(message, kind) {
        statusBox.className = "status" + (kind ? " " + kind : "");
        statusBox.textContent = message;
        statusBox.style.display = "block";
    }

    function hideStatus() {
        statusBox.style.display = "none";
        statusBox.textContent = "";
    }

    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
        return (bytes / (1024 * 1024)).toFixed(1) + " MB";
    }

    function errorMessage(err) {
        if (!err) return "Unknown error";
        if (typeof err === "string") return err;
        return err.message || String(err);
    }

    function setBusy(flag) {
        busy = flag;
        scanBtn.disabled = flag || (!zipFile && phpFiles.length === 0);
        scanBtn.textContent = flag ? "Scanning..." : "Scan Plugin";
    }

    function clearResults() {
        resultsSection.style.display = "none";
        scanSummary.textContent = "";
        findingsBody.textContent = "";
        skippedBody.textContent = "";
        scanNotes.textContent = "";
        reportJson = "";
        downloadJsonBtn.disabled = true;
    }

    // ---------------------------------------------------------------------
    // Python engine
    // ---------------------------------------------------------------------

    async function ensurePyodide() {
        if (pyodide) return pyodide;
        if (typeof window.loadPyodide !== "function") {
            throw new Error("The Pyodide runtime did not load from the CDN. Check your connection and reload the page.");
        }
        pyodide = await window.loadPyodide({ indexURL: PYODIDE_INDEX_URL });
        return pyodide;
    }

    async function ensurePackage() {
        if (packageReady) return;
        await pyodide.runPythonAsync(
            "import pathlib; pathlib.Path('" + PY_PACKAGE_DIR + "').mkdir(parents=True, exist_ok=True)"
        );
        for (const name of VENDORED_MODULES) {
            const response = await fetch("wp_plugin_auditor/" + name);
            if (!response.ok) {
                throw new Error("The vendored module " + name + " could not be loaded (" + response.status + ").");
            }
            const source = await response.text();
            pyodide.FS.writeFile(PY_PACKAGE_DIR + "/" + name, source);
        }
        await pyodide.runPythonAsync("import sys; sys.path.insert(0, '/app')");
        packageReady = true;
    }

    // ---------------------------------------------------------------------
    // Python code
    // ---------------------------------------------------------------------

    /**
     * Archive safety check. It runs before any entry is read and rejects
     * path traversal, absolute paths, symbolic links, duplicate names,
     * encrypted entries, unsupported compression methods, oversized archives
     * and compression-ratio bombs. The check is demo code: the upstream
     * project has no archive support at all.
     */
    function pythonGateCode() {
        return [
            "import json, re, stat, zipfile",
            "archive_path = '" + PY_ARCHIVE_PATH + "'",
            "max_entries = " + LIMITS.maxEntries,
            "max_total_bytes = " + LIMITS.maxTotalBytes,
            "max_ratio = " + LIMITS.maxRatio,
            "reasons = []",
            "entries = []",
            "total_uncompressed = 0",
            "total_compressed = 0",
            "seen = set()",
            "zf = None",
            "try:",
            "    zf = zipfile.ZipFile(archive_path, 'r')",
            "except Exception as exc:",
            "    reasons.append('The file could not be opened as a ZIP archive: ' + str(exc))",
            "if zf is not None:",
            "    try:",
            "        infos = zf.infolist()",
            "        if len(infos) > max_entries:",
            "            reasons.append('The archive holds ' + str(len(infos)) + ' entries, more than the limit of ' + str(max_entries) + '.')",
            "        for info in infos:",
            "            name = info.filename",
            "            normalized = name.replace('\\\\', '/')",
            "            mode = info.external_attr >> 16",
            "            is_symlink = stat.S_ISLNK(mode)",
            "            is_dir = name.endswith('/')",
            "            size = info.file_size",
            "            compressed = info.compress_size",
            "            total_uncompressed += size",
            "            total_compressed += compressed",
            "            if name in seen:",
            "                reasons.append('Duplicate entry name: ' + name)",
            "            seen.add(name)",
            "            if '\\x00' in name:",
            "                reasons.append('Entry name contains a NUL byte.')",
            "            if normalized.startswith('/') or normalized.startswith('//') or re.match(r'^[A-Za-z]:', normalized):",
            "                reasons.append('Absolute path in entry name: ' + name)",
            "            if '..' in normalized.split('/'):",
            "                reasons.append('Path traversal in entry name: ' + name)",
            "            if is_symlink:",
            "                reasons.append('Symbolic link entry: ' + name)",
            "            if info.flag_bits & 0x1:",
            "                reasons.append('Encrypted entry: ' + name)",
            "            if info.compress_type not in (0, 8):",
            "                reasons.append('Unsupported compression method for entry: ' + name)",
            "            entries.append({'name': name, 'size': size, 'is_symlink': is_symlink, 'is_dir': is_dir, 'is_php': normalized.lower().endswith('.php')})",
            "        if total_uncompressed > max_total_bytes:",
            "            reasons.append('The archive expands to ' + str(total_uncompressed) + ' bytes, more than the limit of ' + str(max_total_bytes) + ' bytes.')",
            "        if total_compressed > 0 and total_uncompressed > total_compressed * max_ratio:",
            "            reasons.append('The archive compression ratio is higher than ' + str(max_ratio) + ':1.')",
            "    finally:",
            "        zf.close()",
            "json.dumps({'blocked': bool(reasons), 'reasons': reasons, 'entries': entries, 'total_uncompressed': total_uncompressed})"
        ].join("\n");
    }

    /**
     * The scan itself. It uses the upstream scan_php_file() for every file and
     * the upstream build_report()/report_to_json() for the report, so the rule
     * IDs, severities, line numbers, risk score and JSON schema are the
     * upstream ones. A file that cannot be read is recorded as skipped and the
     * scan continues, which is the documented difference from the CLI.
     */
    function pythonScanCode() {
        return [
            "import dataclasses, json, os, sys",
            "sys.path.insert(0, '/app')",
            "from pathlib import Path",
            "from wp_plugin_auditor.file_scanner import scan_php_file",
            "from wp_plugin_auditor.reporting import build_report, report_to_json",
            "scan_dir = Path('" + PY_SCAN_DIR + "')",
            "label_path = Path('" + PY_LABEL_PATH + "')",
            "max_files = " + LIMITS.maxFiles,
            "max_file_bytes = " + LIMITS.maxFileBytes,
            "max_total_bytes = " + LIMITS.maxTotalBytes,
            "scanned_path = label_path.read_text(encoding='utf-8').strip() if label_path.exists() else ''",
            "if not scanned_path:",
            "    scanned_path = 'upload'",
            "findings = []",
            "scanned = []",
            "skipped = []",
            "total_bytes = 0",
            "for base, dirs, files in os.walk(scan_dir, topdown=True, followlinks=False):",
            "    dirs.sort()",
            "    for name in sorted(files):",
            "        path = Path(base) / name",
            "        try:",
            "            rel = path.relative_to(scan_dir).as_posix()",
            "        except ValueError:",
            "            rel = path.as_posix()",
            "        if path.is_symlink():",
            "            skipped.append({'path': rel, 'reason': 'Symbolic link (skipped).'})",
            "            continue",
            "        if path.suffix.lower() != '.php':",
            "            continue",
            "        if len(scanned) >= max_files:",
            "            skipped.append({'path': rel, 'reason': 'File count limit of ' + str(max_files) + ' reached.'})",
            "            continue",
            "        try:",
            "            size = path.stat().st_size",
            "        except OSError as exc:",
            "            skipped.append({'path': rel, 'reason': 'Could not read the file size: ' + str(exc)})",
            "            continue",
            "        if size > max_file_bytes:",
            "            skipped.append({'path': rel, 'reason': 'File size (' + str(size) + ' bytes) exceeds the per-file limit of ' + str(max_file_bytes) + ' bytes.'})",
            "            continue",
            "        if total_bytes + size > max_total_bytes:",
            "            skipped.append({'path': rel, 'reason': 'Scanning this file would exceed the total limit of ' + str(max_total_bytes) + ' bytes.'})",
            "            continue",
            "        try:",
            "            file_findings = scan_php_file(path, max_bytes=max_file_bytes)",
            "        except ValueError as exc:",
            "            skipped.append({'path': rel, 'reason': str(exc)})",
            "            continue",
            "        except OSError as exc:",
            "            skipped.append({'path': rel, 'reason': 'Could not read the file: ' + str(exc)})",
            "            continue",
            "        total_bytes += size",
            "        scanned.append(rel)",
            "        for finding in file_findings:",
            "            findings.append(dataclasses.replace(finding, file_path=rel))",
            "report = build_report(findings, scanned_path)",
            "json.dumps({'report': report, 'json': report_to_json(report), 'scanned': scanned, 'skipped': skipped, 'total_bytes': total_bytes}, default=str)"
        ].join("\n");
    }

    // ---------------------------------------------------------------------
    // Archive handling
    // ---------------------------------------------------------------------

    function isSafeRelativePath(relativePath) {
        const normalized = String(relativePath).replace(/\\/g, "/");
        if (!normalized || normalized.charAt(0) === "/") return false;
        if (/^[A-Za-z]:/.test(normalized)) return false;
        if (normalized.indexOf("\u0000") !== -1) return false;
        return normalized.split("/").indexOf("..") === -1;
    }

    function ensureMemfsDir(dirPath) {
        if (!dirPath) return;
        try {
            pyodide.FS.mkdirTree(dirPath);
        } catch (e) {
            // The directory most likely exists already; fall back to Python.
            pyodide.globals.set("__memfs_dir", dirPath);
            try {
                pyodide.runPython(
                    "import pathlib\npathlib.Path(__memfs_dir).mkdir(parents=True, exist_ok=True)"
                );
            } catch (inner) {
                // Nothing else to do; the write below reports the problem.
            }
        }
    }

    /**
     * Extract the PHP entries of an accepted archive into the in-memory
     * filesystem. The archive has already passed the safety check; the path is
     * validated again here before anything is written.
     */
    async function extractZipIntoMemory(buffer) {
        const skipped = [];
        const zip = await window.JSZip.loadAsync(buffer);
        const entries = [];
        zip.forEach(function (relativePath, entry) {
            if (entry.dir) return;
            if (!/\.php$/i.test(relativePath)) return;
            entries.push({ path: relativePath, entry: entry });
        });

        for (const item of entries) {
            if (!isSafeRelativePath(item.path)) {
                skipped.push({ path: item.path, reason: "Unsafe path rejected before extraction." });
                continue;
            }
            const bytes = await item.entry.async("uint8array");
            if (bytes.length > LIMITS.maxFileBytes) {
                skipped.push({
                    path: item.path,
                    reason: "File size (" + bytes.length + " bytes) exceeds the per-file limit of " + LIMITS.maxFileBytes + " bytes."
                });
                continue;
            }
            const target = PY_SCAN_DIR + "/" + item.path;
            const slash = target.lastIndexOf("/");
            ensureMemfsDir(target.slice(0, slash));
            try {
                pyodide.FS.writeFile(target, bytes);
            } catch (e) {
                skipped.push({ path: item.path, reason: "Could not store the file locally: " + errorMessage(e) });
            }
        }
        return skipped;
    }

    function safeFileName(name, index, used) {
        const base = String(name || "").split(/[\\/]/).pop();
        let cleaned = base.replace(/[^A-Za-z0-9._-]/g, "_");
        if (!cleaned) cleaned = "file.php";
        if (cleaned.length > 80) cleaned = cleaned.slice(-80);
        let candidate = cleaned;
        let counter = index;
        while (used[candidate]) {
            candidate = counter + "_" + cleaned;
            counter += 1;
        }
        used[candidate] = true;
        return candidate;
    }

    /**
     * Copy the selected PHP files into the in-memory filesystem. File names
     * are sanitised because a browser cannot expose a real directory.
     */
    async function writePhpFilesIntoMemory() {
        const skipped = [];
        const used = {};
        let total = 0;

        for (let i = 0; i < phpFiles.length; i++) {
            const file = phpFiles[i];
            const name = safeFileName(file.name, i, used);
            if (file.size > LIMITS.maxFileBytes) {
                skipped.push({
                    path: name,
                    reason: "File size (" + file.size + " bytes) exceeds the per-file limit of " + LIMITS.maxFileBytes + " bytes."
                });
                continue;
            }
            if (total + file.size > LIMITS.maxTotalBytes) {
                skipped.push({
                    path: name,
                    reason: "Scanning this file would exceed the total limit of " + LIMITS.maxTotalBytes + " bytes."
                });
                continue;
            }
            total += file.size;
            try {
                const buffer = await file.arrayBuffer();
                ensureMemfsDir(PY_SCAN_DIR);
                pyodide.FS.writeFile(PY_SCAN_DIR + "/" + name, new Uint8Array(buffer));
            } catch (e) {
                skipped.push({ path: name, reason: "Could not store the file locally: " + errorMessage(e) });
            }
        }
        return skipped;
    }

    // ---------------------------------------------------------------------
    // Scan
    // ---------------------------------------------------------------------

    async function runAudit() {
        if (busy) return;
        if (!zipFile && phpFiles.length === 0) return;

        hideStatus();
        setBusy(true);
        clearResults();

        let jsSkipped = [];

        try {
            showStatus("Loading the local Python engine. The first run downloads the Pyodide runtime and can take around 30 seconds...", "info");
            await ensurePyodide();
            await ensurePackage();

            let label = "upload";

            if (zipFile) {
                label = zipFile.name;
                if (zipFile.size > LIMITS.maxUploadBytes) {
                    showStatus(
                        "The archive is " + formatBytes(zipFile.size) + ", which is larger than the " +
                        formatBytes(LIMITS.maxUploadBytes) + " upload limit. Nothing was read.",
                        "danger"
                    );
                    return;
                }

                showStatus("Checking the archive for unsafe entries before anything is read...", "info");
                const buffer = await zipFile.arrayBuffer();
                pyodide.FS.writeFile(PY_ARCHIVE_PATH, new Uint8Array(buffer));

                const gateOutput = await pyodide.runPythonAsync(pythonGateCode());
                const gate = JSON.parse(String(gateOutput));
                if (gate.blocked) {
                    showStatus("The archive was rejected before extraction: " + gate.reasons.join(" "), "danger");
                    renderGateReasons(gate.reasons);
                    return;
                }

                showStatus("Copying the plugin files into local memory...", "info");
                jsSkipped = await extractZipIntoMemory(buffer);
            } else {
                label = phpFiles.length === 1 ? phpFiles[0].name : phpFiles.length + " PHP files";
                showStatus("Copying the selected PHP files into local memory...", "info");
                jsSkipped = await writePhpFilesIntoMemory();
            }

            pyodide.FS.writeFile(PY_LABEL_PATH, label);

            showStatus("Scanning the PHP files for risky patterns...", "info");
            const scanOutput = await pyodide.runPythonAsync(pythonScanCode());
            const payload = JSON.parse(String(scanOutput));
            payload.skipped = (jsSkipped || []).concat(payload.skipped || []);

            renderResults(payload);

            const summary = payload.report.summary;
            if (!summary.total_findings) {
                showStatus(
                    "Scan finished: no risky pattern was matched in " + payload.scanned.length +
                    " file(s). The scanner is a regular-expression heuristic, not a PHP parser, so this is not a clean bill of health.",
                    "success"
                );
            } else {
                showStatus(
                    "Scan finished: " + summary.total_findings + " finding(s) with a risk score of " +
                    summary.risk_score + " across " + payload.scanned.length + " file(s).",
                    "warning"
                );
            }
        } catch (err) {
            showStatus("The scan failed: " + errorMessage(err), "danger");
        } finally {
            cleanupFilesystem();
            setBusy(false);
        }
    }

    /**
     * Remove everything the scan created in the in-memory filesystem. Called
     * after every run, including failed runs.
     */
    function cleanupFilesystem() {
        if (!pyodide) return;
        [PY_ARCHIVE_PATH, PY_LABEL_PATH].forEach(function (path) {
            try {
                pyodide.FS.unlink(path);
            } catch (e) {
                // Nothing to remove.
            }
        });
        try {
            pyodide.FS.rmdir(PY_SCAN_DIR, { recursive: true });
        } catch (e) {
            // Nothing to remove.
        }
    }

    // ---------------------------------------------------------------------
    // Rendering
    // ---------------------------------------------------------------------

    function renderGateReasons(reasons) {
        resultsSection.style.display = "block";
        scanSummary.textContent = "";
        findingsBody.textContent = "";
        skippedBody.textContent = "";
        scanNotes.textContent = "";

        const list = el("ul", "notes");
        reasons.forEach(function (reason) {
            list.appendChild(el("li", null, reason));
        });
        scanNotes.appendChild(list);
        scanNotes.appendChild(el("p", "note",
            "The archive was rejected before any entry was read, so no file from it reached the scanner. " +
            "Remove the unsafe entries and try again, or scan the plugin directory with the command-line tool."));
    }

    function renderResults(payload) {
        resultsSection.style.display = "block";

        const report = payload.report;
        const summary = report.summary;
        const bySeverity = summary.by_severity || {};

        scanSummary.textContent = "";
        const items = [
            [String(payload.scanned.length), "Files Scanned"],
            [String(summary.total_findings), "Findings"],
            [String(summary.risk_score), "Risk Score"],
            [String(bySeverity.CRITICAL || 0), "Critical"],
            [String(bySeverity.HIGH || 0), "High"],
            [String(bySeverity.MEDIUM || 0), "Medium"],
            [String(payload.skipped.length), "Skipped"]
        ];
        items.forEach(function (item) {
            const box = el("div", "summary-item");
            box.appendChild(el("span", "count", item[0]));
            box.appendChild(el("span", "label", item[1]));
            scanSummary.appendChild(box);
        });

        findingsBody.textContent = "";
        if (!report.findings.length) {
            const row = document.createElement("tr");
            const cell = el("td", null, "No risky pattern was matched.");
            cell.colSpan = 6;
            row.appendChild(cell);
            findingsBody.appendChild(row);
        } else {
            report.findings.forEach(function (finding) {
                const row = document.createElement("tr");

                const severityCell = document.createElement("td");
                severityCell.appendChild(badge(String(finding.severity || "").toUpperCase(), severityClass(finding.severity)));
                row.appendChild(severityCell);

                row.appendChild(el("td", "rule", finding.rule_id || "-"));
                row.appendChild(el("td", "path", finding.file_path || "-"));
                row.appendChild(el("td", null, finding.line_number === null || finding.line_number === undefined ? "-" : String(finding.line_number)));
                row.appendChild(el("td", null, finding.description || "-"));
                row.appendChild(el("td", null, finding.recommendation || "-"));

                findingsBody.appendChild(row);
            });
        }

        skippedBody.textContent = "";
        if (!payload.skipped.length) {
            const row = document.createElement("tr");
            const cell = el("td", null, "No file was skipped.");
            cell.colSpan = 2;
            row.appendChild(cell);
            skippedBody.appendChild(row);
        } else {
            payload.skipped.forEach(function (item) {
                const row = document.createElement("tr");
                row.appendChild(el("td", "path", item.path || "-"));
                row.appendChild(el("td", null, item.reason || "-"));
                skippedBody.appendChild(row);
            });
        }

        scanNotes.textContent = "";
        scanNotes.appendChild(el("p", "note",
            "Every finding is a regular-expression match produced by the upstream scanner. It is not a confirmed " +
            "vulnerability, and the risk score (" + summary.risk_score + ") is a prioritisation aid that sums the " +
            "severity weights, not a security metric."));
        scanNotes.appendChild(el("p", "note",
            "Source: " + report.scanned_path + ". The upstream tool records the directory it scanned in this field; " +
            "this demo records the name of the uploaded archive or the selected files."));

        reportJson = payload.json;
        downloadJsonBtn.disabled = false;
    }

    function downloadReport() {
        if (!reportJson) return;
        const blob = new Blob([reportJson], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = "plugin-audit-report.json";
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.setTimeout(function () {
            URL.revokeObjectURL(url);
        }, 1000);
    }

    // ---------------------------------------------------------------------
    // Input handling
    // ---------------------------------------------------------------------

    function acceptZip(file) {
        if (!file) return;
        if (!/\.zip$/i.test(file.name)) {
            showStatus("Only a .zip plugin archive can be used here. Select individual .php files instead.", "danger");
            return;
        }
        if (file.size > LIMITS.maxUploadBytes) {
            showStatus(
                "The archive is " + formatBytes(file.size) + ", which is larger than the " +
                formatBytes(LIMITS.maxUploadBytes) + " upload limit.",
                "danger"
            );
            return;
        }
        zipFile = file;
        phpFiles = [];
        phpInput.value = "";
        fileInfo.textContent = file.name + " (" + formatBytes(file.size) + ")";
        clearResults();
        setBusy(false);
    }

    function acceptPhpFiles(fileList) {
        const files = [];
        for (let i = 0; i < fileList.length; i++) {
            const file = fileList[i];
            if (!/\.php$/i.test(file.name)) {
                showStatus("Only .php files can be scanned. \"" + file.name + "\" was ignored.", "warning");
                continue;
            }
            files.push(file);
        }
        if (!files.length) return;
        if (files.length > LIMITS.maxFiles) {
            showStatus(
                "Only the first " + LIMITS.maxFiles + " of " + files.length + " selected files can be scanned.",
                "warning"
            );
        }
        zipFile = null;
        zipInput.value = "";
        phpFiles = files;
        const total = files.reduce(function (sum, file) { return sum + file.size; }, 0);
        fileInfo.textContent = files.length + " PHP file(s) selected (" + formatBytes(total) + ")";
        clearResults();
        setBusy(false);
    }

    function clearAll() {
        zipFile = null;
        phpFiles = [];
        zipInput.value = "";
        phpInput.value = "";
        fileInfo.textContent = "Nothing selected";
        clearResults();
        hideStatus();
        setBusy(false);
    }

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    function init() {
        chooseZipBtn.addEventListener("click", function () { zipInput.click(); });
        choosePhpBtn.addEventListener("click", function () { phpInput.click(); });

        zipInput.addEventListener("change", function () {
            acceptZip(zipInput.files && zipInput.files[0]);
        });
        phpInput.addEventListener("change", function () {
            acceptPhpFiles(phpInput.files || []);
        });

        uploadArea.addEventListener("dragover", function (event) {
            event.preventDefault();
            uploadArea.classList.add("dragover");
        });
        uploadArea.addEventListener("dragleave", function () {
            uploadArea.classList.remove("dragover");
        });
        uploadArea.addEventListener("drop", function (event) {
            event.preventDefault();
            uploadArea.classList.remove("dragover");
            const files = event.dataTransfer && event.dataTransfer.files;
            if (!files || !files.length) return;
            if (files.length === 1 && /\.zip$/i.test(files[0].name)) {
                acceptZip(files[0]);
            } else {
                acceptPhpFiles(files);
            }
        });

        scanBtn.addEventListener("click", runAudit);
        clearBtn.addEventListener("click", clearAll);
        downloadJsonBtn.addEventListener("click", downloadReport);

        window.addEventListener("error", function (event) {
            showStatus("Unexpected error: " + errorMessage(event.error || event.message), "danger");
        });
        window.addEventListener("unhandledrejection", function (event) {
            showStatus("Unexpected error: " + errorMessage(event.reason), "danger");
        });

        showStatus("Ready. Choose a plugin ZIP or one or more .php files, then run \"Scan Plugin\".", "info");
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
