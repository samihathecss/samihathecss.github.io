/**
 * WP Forensics & Recovery Assistant - Browser Demo
 *
 * Milestone 2.1: ZIP archive inspection.
 * The uploaded archive is written into the Pyodide in-memory filesystem and
 * inspected by the upstream `inspect_zip()` implementation (vendored
 * verbatim - see VENDORED.md). No entry is extracted and no file content is
 * read in this milestone.
 *
 * Milestone 2.4: snapshot comparison.
 * Two archives are inspected with the same safety gate, extracted into two
 * separate in-memory directories and compared by the upstream
 * `compare.compare_snapshots()` implementation.
 *
 * Milestone 2.5: partial WordPress core verification.
 * The archive is extracted into a dedicated scratch directory, the official
 * WordPress.org checksums are fetched by the browser (the Python runtime in
 * the page has no network access), and the extracted files are compared by the
 * upstream `core_verify.verify_core()` implementation. The upstream module
 * performs its own urllib request, so the browser fetch is injected at the
 * `urllib.request.urlopen` boundary; the vendored code is not modified.
 *
 * All untrusted values (archive entry names, error messages) are written with
 * textContent only. No innerHTML rendering is used anywhere in this file.
 */

(function () {
  "use strict";

  // ZIP safety and resource limits for the browser demo.
  // Declared ZIP metadata alone does not guarantee protection against ZIP bombs;
  // these limits are conservative, documented defaults and are not benchmarked capacity figures.
  // Adjust all values in this single block.
  const ZIP_SAFETY = {
    // Maximum compressed (on-disk/upload) size of a single ZIP archive (bytes).
    maxCompressedSize: 25 * 1024 * 1024,   // 25 MB
    // Maximum total uncompressed size of all entries combined (bytes).
    maxUncompressedSize: 50 * 1024 * 1024, // 50 MB
    // Maximum number of entries per archive.
    maxFileCount: 2000,
    // Maximum number of files the scanner will process.
    maxScannedFiles: 1000,
    // Maximum size of a single file (bytes).
    maxFileSize: 5 * 1024 * 1024,          // 5 MB
    // Maximum allowed compression ratio (uncompressed / compressed).
    maxCompressionRatio: 100,
    // Maximum time allowed for a single archive operation (seconds).
    scanTimeoutSeconds: 60
  };

  // Core verification limits. The response cap and the request timeout mirror
  // the values used by the upstream core_verify module.
  const CORE_VERIFY = {
    // Official checksum service of the WordPress.org API.
    apiUrl: "https://api.wordpress.org/core/checksums/1.0/",
    // Maximum size of the checksum response accepted from the network (bytes).
    maxResponseBytes: 1024 * 1024, // 1 MB
    // Maximum time allowed for the checksum request (seconds).
    requestTimeoutSeconds: 15,
    // Maximum number of per-file rows rendered on screen.
    maxListedFiles: 500
  };

  // Vendored upstream package (see VENDORED.md). Files are loaded from this
  // demo folder into the Pyodide filesystem; no code is fetched from a remote
  // origin at runtime.
  const VENDORED_PACKAGE = "wp_forensics";
  const VENDORED_FILES = [
    "__init__.py",
    "archive.py",
    "compare.py",
    "config.py",
    "core_verify.py",
    "hashing.py",
    "indicators.py",
    "models.py",
    "report.py",
    "version.py"
  ];
  const PY_APP_DIR = "/app";
  const PY_PACKAGE_DIR = PY_APP_DIR + "/wp_forensics";
  const PY_ARCHIVE_PATH = "/tmp/input.zip";
  // Dedicated scratch directory for extracted files. Extraction never happens
  // anywhere else in the in-memory filesystem.
  const PY_SCAN_DIR = "/tmp/wp-scan";
  // Snapshot comparison (milestone 2.4). Each archive keeps its own path and
  // its own extraction directory so the two snapshots stay separated.
  const PY_COMPARE_A_PATH = "/tmp/wp-compare-a.zip";
  const PY_COMPARE_B_PATH = "/tmp/wp-compare-b.zip";
  const PY_COMPARE_A_DIR = "/tmp/wp-compare-a";
  const PY_COMPARE_B_DIR = "/tmp/wp-compare-b";
  // Core verification (milestone 2.5). The archive is extracted into its own
  // scratch directory, the official checksums are staged in a file, and the
  // detected installation root is passed back to Python through a file so that
  // no archive-derived string is ever embedded in generated Python source.
  const PY_VERIFY_DIR = "/tmp/wp-verify";
  const PY_CHECKSUMS_PATH = "/tmp/wp-checksums.json";
  const PY_VERIFY_ROOT_PATH = "/tmp/wp-verify-root.txt";
  const PY_VERIFY_ERROR_PATH = "/tmp/wp-verify-error.txt";

  // Base URL of this demo folder, resolved from the running script so the
  // package files are found regardless of the trailing-slash form of the URL.
  var SCRIPT_URL = (document.currentScript && document.currentScript.src) || "";
  var APP_BASE = SCRIPT_URL ? new URL(".", SCRIPT_URL).href : new URL(".", window.location.href).href;

  var pyodide = null;
  var initPromise = null;
  var packagePromise = null;
  var packageReady = false;
  var selectedFile = null;
  var compareFileA = null;
  var compareFileB = null;
  var comparisonResult = null;
  var busy = false;

  var uploadArea = document.getElementById("upload-area");
  var fileInput = document.getElementById("zip-input");
  var fileInfo = document.getElementById("file-info");
  var inspectBtn = document.getElementById("inspect-btn");
  var scanBtn = document.getElementById("scan-btn");
  var clearBtn = document.getElementById("clear-btn");
  var statusDiv = document.getElementById("status");
  var resultsSection = document.getElementById("results-section");
  var summaryGrid = document.getElementById("summary-grid");
  var entriesBody = document.getElementById("entries-body");
  var inspectionNotes = document.getElementById("inspection-notes");
  var scanSection = document.getElementById("scan-section");
  var scanSummary = document.getElementById("scan-summary");
  var findingsBody = document.getElementById("findings-body");
  var scanNotes = document.getElementById("scan-notes");
  var downloadJsonBtn = document.getElementById("download-json");
  var downloadHtmlBtn = document.getElementById("download-html");
  var omitEvidenceToggle = document.getElementById("omit-evidence");
  var scanAvailable = false;
  var compareBtn = document.getElementById("compare-btn");
  var compareAInfo = document.getElementById("compare-a-info");
  var compareBInfo = document.getElementById("compare-b-info");
  var compareResultsSection = document.getElementById("compare-results-section");
  var compareSummary = document.getElementById("compare-summary");
  var compareEntriesBody = document.getElementById("compare-entries-body");
  var compareNotes = document.getElementById("compare-notes");
  var downloadCompareJsonBtn = document.getElementById("download-compare-json");
  var verifyBtn = document.getElementById("verify-btn");
  var verifySection = document.getElementById("verify-section");
  var verifySummary = document.getElementById("verify-summary");
  var verifyFilesBody = document.getElementById("verify-files-body");
  var verifyNotes = document.getElementById("verify-notes");

  function showStatus(message, type) {
    statusDiv.textContent = message;
    statusDiv.className = "status " + (type || "info");
    statusDiv.style.display = "block";
  }

  function hideStatus() {
    statusDiv.style.display = "none";
    statusDiv.textContent = "";
  }

  function formatBytes(n) {
    if (n === 0 || n === null || n === undefined) return "-";
    var units = ["B", "KB", "MB", "GB"];
    var i = 0;
    var v = Number(n);
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i++;
    }
    return v.toFixed(1) + " " + units[i];
  }

  function errorMessage(err) {
    if (!err) return "Unknown error";
    if (typeof err === "string") return err;
    if (err.message) return String(err.message);
    try {
      return String(err);
    } catch (e) {
      return "Unknown error";
    }
  }

  function isZipFile(file) {
    if (!file) return false;
    if (/\.zip$/i.test(file.name)) return true;
    var type = (file.type || "").toLowerCase();
    return type === "application/zip" ||
      type === "application/x-zip-compressed" ||
      type === "application/x-zip";
  }

  function updateActionStates() {
    inspectBtn.disabled = !selectedFile;
    scanBtn.disabled = !selectedFile;
    if (verifyBtn) verifyBtn.disabled = !selectedFile || busy;
    updateCompareState();
  }

  function resetSelection(message, type) {
    selectedFile = null;
    fileInfo.textContent = "No file selected";
    fileInput.value = "";
    updateActionStates();
    if (message) showStatus(message, type);
  }

  function clearResults() {
    resultsSection.style.display = "none";
    summaryGrid.textContent = "";
    entriesBody.textContent = "";
    inspectionNotes.textContent = "";
  }

  function clearScanResults() {
    scanSection.style.display = "none";
    scanSummary.textContent = "";
    findingsBody.textContent = "";
    scanNotes.textContent = "";
  }

  function setReportAvailability(available) {
    scanAvailable = available;
    downloadJsonBtn.disabled = !available;
    downloadHtmlBtn.disabled = !available;
  }

  /**
   * Generate a report in the browser and hand it to the visitor as a file.
   * The report text is only ever placed in a Blob; it is never inserted into
   * the page and the HTML report is never opened automatically.
   */
  function downloadReport(mode) {
    if (!scanAvailable) return;

    downloadJsonBtn.disabled = true;
    downloadHtmlBtn.disabled = true;
    showStatus("Generating the report in your browser...", "info");

    pyodide.runPythonAsync(buildReportCode(mode, omitEvidenceToggle.checked))
      .then(function (output) {
        var payload = JSON.parse(String(output));
        var reportText = payload.report;
        var isJson = mode === "json";
        var blob = new Blob([reportText], {
          type: isJson ? "application/json" : "text/html;charset=utf-8"
        });
        var url = URL.createObjectURL(blob);
        var link = document.createElement("a");
        link.href = url;
        link.download = isJson ? "wp-forensics-scan-report.json" : "wp-forensics-scan-report.html";
        link.style.display = "none";
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        setTimeout(function () {
          URL.revokeObjectURL(url);
        }, 2000);
        showStatus(
          isJson
            ? "JSON report generated locally and saved to your device."
            : "HTML report generated locally and saved to your device. Open it from your downloads - it is never loaded into this page.",
          "success"
        );
      })
      .catch(function (err) {
        showStatus("Report generation failed: " + errorMessage(err), "danger");
      })
      .then(function () {
        downloadJsonBtn.disabled = !scanAvailable;
        downloadHtmlBtn.disabled = !scanAvailable;
      });
  }

  function acceptFile(file) {
    if (!file) return;

    if (!isZipFile(file)) {
      resetSelection(
        "That file is not a ZIP archive. Choose a .zip file, such as a WordPress backup archive.",
        "danger"
      );
      return;
    }

    if (file.size > ZIP_SAFETY.maxCompressedSize) {
      resetSelection(
        "Archive is " + formatBytes(file.size) + ", above the " +
        formatBytes(ZIP_SAFETY.maxCompressedSize) + " upload limit. Nothing was read or extracted.",
        "danger"
      );
      return;
    }

    selectedFile = file;
    fileInfo.textContent = file.name + " (" + formatBytes(file.size) + ")";
    clearResults();
    clearScanResults();
    clearCoreVerifyResults();
    setReportAvailability(false);
    updateActionStates();
    showStatus(
      "Archive accepted (" + formatBytes(file.size) + "). It has not been extracted or read yet. " +
      "Initialising the local engine...",
      "info"
    );
    initEngine();
  }

  function ensurePyodide() {
    if (pyodide) return Promise.resolve(pyodide);
    if (initPromise) return initPromise;

    if (typeof window.loadPyodide !== "function") {
      return Promise.reject(
        new Error("The Pyodide runtime did not load from the CDN. Check your network connection and reload the page.")
      );
    }
    if (typeof window.JSZip === "undefined") {
      return Promise.reject(
        new Error("The JSZip library did not load from the CDN. Check your network connection and reload the page.")
      );
    }

    showStatus("Loading Pyodide (first load may take ~30s)...", "info");

    initPromise = window.loadPyodide()
      .then(function (py) {
        pyodide = py;
        return pyodide;
      })
      .catch(function (err) {
        initPromise = null;
        throw err;
      });

    return initPromise;
  }

  function initEngine() {
    ensurePyodide()
      .then(function () {
        showStatus(
          "Engine ready. Use \"Inspect ZIP\" to check the archive safety before anything is extracted.",
          "success"
        );
      })
      .catch(function (err) {
        showStatus("Engine initialisation failed: " + errorMessage(err), "danger");
      });
  }

  /**
   * Copy the vendored upstream package into the Pyodide filesystem and import
   * it. The files are served from this demo folder, never from a remote origin.
   */
  function ensurePackage() {
    if (packageReady) return Promise.resolve();
    if (packagePromise) return packagePromise;

    packagePromise = (function () {
      try {
        pyodide.FS.mkdirTree(PY_PACKAGE_DIR);
      } catch (e) {
        try {
          pyodide.FS.mkdir(PY_PACKAGE_DIR);
        } catch (e2) {
          // Directory already exists.
        }
      }

      var chain = Promise.resolve();
      VENDORED_FILES.forEach(function (fn) {
        chain = chain.then(function () {
          return fetch(APP_BASE + VENDORED_PACKAGE + "/" + fn)
            .then(function (resp) {
              if (!resp.ok) {
                throw new Error("Failed to load package file: " + fn);
              }
              return resp.arrayBuffer();
            })
            .then(function (buffer) {
              pyodide.FS.writeFile(PY_PACKAGE_DIR + "/" + fn, new Uint8Array(buffer));
            });
        });
      });

      return chain
        .then(function () {
          return pyodide.runPythonAsync(
            "import sys\n" +
            "sys.path.insert(0, '" + PY_APP_DIR + "')\n" +
            "import wp_forensics\n" +
            "assert hasattr(wp_forensics, 'inspect_zip')\n"
          );
        })
        .then(function () {
          packageReady = true;
        })
        .catch(function (err) {
          packagePromise = null;
          throw err;
        });
    })();

    return packagePromise;
  }

  /**
   * Shared Python preamble: runs the upstream inspect_zip() with the browser
   * limit set and adds the strict S_IFLNK symlink check used by the demo.
   * The vendored upstream code is not modified.
   */
  function pythonInspectLines() {
    return [
      "import json, sys, dataclasses, zipfile",
      "sys.path.insert(0, '" + PY_APP_DIR + "')",
      "from pathlib import Path",
      "from wp_forensics import inspect_zip",
      "from wp_forensics.config import ScanConfig",
      "config = ScanConfig(",
      "    max_file_size_bytes=" + ZIP_SAFETY.maxFileSize + ",",
      "    max_file_count=" + ZIP_SAFETY.maxScannedFiles + ",",
      "    max_total_size_bytes=" + ZIP_SAFETY.maxUncompressedSize + ",",
      "    scan_timeout_seconds=" + ZIP_SAFETY.scanTimeoutSeconds + ",",
      "    zip_max_entries=" + ZIP_SAFETY.maxFileCount + ",",
      "    zip_max_compressed_bytes=" + ZIP_SAFETY.maxCompressedSize + ",",
      "    zip_max_uncompressed_bytes=" + ZIP_SAFETY.maxUncompressedSize + ",",
      "    zip_max_ratio=" + ZIP_SAFETY.maxCompressionRatio + ",",
      ")",
      "archive_path = Path('" + PY_ARCHIVE_PATH + "')",
      "inspection = inspect_zip(archive_path, config)",
      "insp = dataclasses.asdict(inspection)",
      "# Demo-layer strict symlink check. The upstream helper compares the whole",
      "# 16-bit mode to 0o120000, so symlinks carrying ordinary permission bits",
      "# (for example 0o120755) are not flagged. The standard S_IFLNK type-bit",
      "# mask is applied here as well; the vendored upstream code is unmodified.",
      "strict_symlinks = []",
      "try:",
      "    with zipfile.ZipFile(archive_path, 'r') as zf:",
      "        for info in zf.infolist():",
      "            strict_symlinks.append(((info.external_attr >> 16) & 0o170000) == 0o120000)",
      "except Exception:",
      "    strict_symlinks = []",
      "for idx, entry in enumerate(insp.get('entries', [])):",
      "    entry['strict_symlink'] = bool(strict_symlinks[idx]) if idx < len(strict_symlinks) else False",
      "insp['strict_symlink_count'] = sum(1 for e in insp.get('entries', []) if e.get('strict_symlink'))"
    ];
  }

  /**
   * Python code executed for each inspection. It calls the upstream
   * inspect_zip() with the browser limit set and returns the result as JSON.
   */
  function buildInspectCode() {
    return pythonInspectLines().concat([
      "json.dumps(insp, default=str)"
    ]).join("\n");
  }

  /**
   * Pre-extraction safety gate. The archive is only extracted when no blocking
   * condition is found: symlink entries (strict type-bit check), path traversal
   * entries, duplicate entries, inspection errors, or archives over the
   * configured limits.
   */
  function buildGateCode() {
    return pythonInspectLines().concat([
      "reasons = []",
      "for e in insp.get('entries', []):",
      "    if e.get('strict_symlink'):",
      "        reasons.append('symlink entry: ' + e['name'])",
      "    if e.get('is_traversal_risk'):",
      "        reasons.append('path traversal entry: ' + e['name'])",
      "    if e.get('is_duplicate'):",
      "        reasons.append('duplicate entry: ' + e['name'])",
      "for m in insp.get('errors', []):",
      "    reasons.append('inspection error: ' + m)",
      "if insp.get('total_entries', 0) > config.zip_max_entries:",
      "    reasons.append('archive entry count exceeds the limit of ' + str(config.zip_max_entries))",
      "if insp.get('total_uncompressed_bytes', 0) > config.zip_max_uncompressed_bytes:",
      "    reasons.append('archive uncompressed size exceeds the limit')",
      "if insp.get('total_compressed_bytes', 0) > config.zip_max_compressed_bytes:",
      "    reasons.append('archive compressed size exceeds the limit')",
      "json.dumps({'blocked': bool(reasons), 'reasons': reasons, 'inspection': insp}, default=str)"
    ]).join("\n");
  }

  /**
   * Python helper lines: sensitive-file detection and evidence redaction.
   * Applied to the on-screen findings and to the downloadable reports.
   * Sensitive files: wp-config.php, .env, *.pem, *.key, id_rsa, names
   * containing "credentials", and *.sql.
   */
  function pythonRedactionLines() {
    return [
      "import posixpath",
      "SENSITIVE_NAMES = ('wp-config.php', '.env', 'id_rsa')",
      "SENSITIVE_EXTS = ('.pem', '.key', '.sql')",
      "def _is_sensitive(path):",
      "    name = posixpath.basename(str(path).replace(chr(92), '/')).lower()",
      "    if name in SENSITIVE_NAMES:",
      "        return True",
      "    if name.startswith('.env') or name.startswith('id_rsa'):",
      "        return True",
      "    if 'credentials' in name:",
      "        return True",
      "    return posixpath.splitext(name)[1] in SENSITIVE_EXTS",
      "def _redact_findings(result, omit_all=False):",
      "    for finding in result.findings:",
      "        if omit_all:",
      "            finding.evidence = '[evidence omitted]'",
      "        elif _is_sensitive(finding.file_path):",
      "            finding.evidence = '[redacted: sensitive file]'"
    ];
  }

  /**
   * Python code executed for the scan. Extraction uses the upstream
   * safe_extract_zip() and is confined to a dedicated scratch directory;
   * the scan uses the upstream indicators.scan_directory(). A pristine copy of
   * the result is kept in the browser session for later report generation.
   */
  function buildScanCode() {
    return pythonInspectLines().concat([
      "from wp_forensics import safe_extract_zip",
      "from wp_forensics.indicators import scan_directory",
      "dest = Path('" + PY_SCAN_DIR + "')",
      "extracted = safe_extract_zip(archive_path, dest, config)",
      "scan_obj = scan_directory(dest, config)",
      "import builtins, copy",
      "pristine = copy.deepcopy(scan_obj)"
    ]).concat(pythonRedactionLines()).concat([
      "_redact_findings(scan_obj, omit_all=False)",
      "builtins._wpforensics_demo_scan_pristine = pristine",
      "scan = dataclasses.asdict(scan_obj)",
      "json.dumps({'extracted_count': len(extracted), 'scan': scan}, default=str)"
    ]).join("\n");
  }

  /**
   * Python code executed for each report download. The report is regenerated
   * from the pristine scan result with the current redaction settings and is
   * returned as a string. The HTML report is only ever used as a download.
   */
  function buildReportCode(mode, omitEvidence) {
    var omitLiteral = omitEvidence ? "True" : "False";
    return pythonRedactionLines().concat([
      "import builtins, copy, json, sys",
      "sys.path.insert(0, '" + PY_APP_DIR + "')",
      "from wp_forensics.report import generate_json_report, generate_html_report",
      "MODE = '" + mode + "'",
      "pristine = getattr(builtins, '_wpforensics_demo_scan_pristine', None)",
      "if pristine is None:",
      "    raise RuntimeError('No completed scan is available for reporting.')",
      "result = copy.deepcopy(pristine)",
      "_redact_findings(result, omit_all=" + omitLiteral + ")",
      "REPORT = generate_json_report(result) if MODE == 'json' else generate_html_report(result)",
      "json.dumps({'report': REPORT}, default=str)"
    ]).join("\n");
  }

  /**
   * Limit set shared by the snapshot comparison steps. The values come from
   * the same ZIP_SAFETY block that the inspection preamble uses, so both
   * snapshots are extracted and hashed under identical limits.
   */
  function pythonCompareConfigLines() {
    return [
      "import sys",
      "sys.path.insert(0, '" + PY_APP_DIR + "')",
      "from wp_forensics.config import ScanConfig",
      "config = ScanConfig(",
      "    max_file_size_bytes=" + ZIP_SAFETY.maxFileSize + ",",
      "    max_file_count=" + ZIP_SAFETY.maxScannedFiles + ",",
      "    max_total_size_bytes=" + ZIP_SAFETY.maxUncompressedSize + ",",
      "    scan_timeout_seconds=" + ZIP_SAFETY.scanTimeoutSeconds + ",",
      "    zip_max_entries=" + ZIP_SAFETY.maxFileCount + ",",
      "    zip_max_compressed_bytes=" + ZIP_SAFETY.maxCompressedSize + ",",
      "    zip_max_uncompressed_bytes=" + ZIP_SAFETY.maxUncompressedSize + ",",
      "    zip_max_ratio=" + ZIP_SAFETY.maxCompressionRatio + ",",
      ")"
    ];
  }

  /**
   * Python code executed to extract both snapshots. The upstream
   * safe_extract_zip() is used for both archives and each snapshot gets its
   * own directory. Extraction only runs after both archives passed the
   * inspection gate.
   */
  function buildCompareExtractCode() {
    return pythonCompareConfigLines().concat([
      "import json, shutil",
      "from pathlib import Path",
      "from wp_forensics import safe_extract_zip",
      "dest_a = Path('" + PY_COMPARE_A_DIR + "')",
      "dest_b = Path('" + PY_COMPARE_B_DIR + "')",
      "for dest in (dest_a, dest_b):",
      "    if dest.exists():",
      "        shutil.rmtree(dest)",
      "archive_a = Path('" + PY_COMPARE_A_PATH + "')",
      "archive_b = Path('" + PY_COMPARE_B_PATH + "')",
      "extracted_a = safe_extract_zip(archive_a, dest_a, config)",
      "extracted_b = safe_extract_zip(archive_b, dest_b, config)",
      "json.dumps({'extracted_a': len(extracted_a), 'extracted_b': len(extracted_b)}, default=str)"
    ]).join("\n");
  }

  /**
   * Python code executed to compare the two extracted snapshots. The upstream
   * compare.compare_snapshots() implementation does the whole comparison and
   * the upstream report generator produces the downloadable JSON file.
   * The upstream hashing helper writes progress notes to stdout, so stdout is
   * redirected while the comparison runs to keep the payload clean.
   */
  function buildCompareCode() {
    return pythonCompareConfigLines().concat([
      "import io, json, sys, dataclasses",
      "from pathlib import Path",
      "from wp_forensics.compare import compare_snapshots",
      "from wp_forensics.report import generate_json_report",
      "source = Path('" + PY_COMPARE_A_DIR + "')",
      "dest = Path('" + PY_COMPARE_B_DIR + "')",
      "saved_stdout = sys.stdout",
      "sys.stdout = io.StringIO()",
      "try:",
      "    comparison = compare_snapshots(source, dest, config)",
      "    report = generate_json_report(comparison)",
      "    data = dataclasses.asdict(comparison)",
      "finally:",
      "    sys.stdout = saved_stdout",
      "json.dumps({'report': report, 'comparison': data}, default=str)"
    ]).join("\n");
  }

  /**
   * Limit set shared by the core verification steps. It is the same limit set
   * the inspection preamble and the snapshot comparison use, so an archive is
   * read under identical limits in every feature.
   */
  function pythonCoreConfigLines() {
    return pythonCompareConfigLines();
  }

  /**
   * Python code executed before the checksum request. The upstream
   * safe_extract_zip() writes the archive into a dedicated scratch directory
   * and the upstream version detection finds the WordPress root and the
   * version/locale. The root path is written to a file so that the next step
   * never has to embed an archive-derived string in generated source.
   */
  function buildCoreDetectCode() {
    return pythonCoreConfigLines().concat([
      "import io, json, shutil, sys",
      "from pathlib import Path",
      "from wp_forensics import safe_extract_zip",
      "from wp_forensics.version import detect_wordpress_info",
      "dest = Path('" + PY_VERIFY_DIR + "')",
      "if dest.exists():",
      "    shutil.rmtree(dest)",
      "archive_path = Path('" + PY_ARCHIVE_PATH + "')",
      "saved_stdout = sys.stdout",
      "sys.stdout = io.StringIO()",
      "try:",
      "    extracted = safe_extract_zip(archive_path, dest, config)",
      "    candidates = [dest]",
      "    try:",
      "        candidates.extend(sorted(p for p in dest.iterdir() if p.is_dir()))",
      "    except OSError:",
      "        pass",
      "    root = None",
      "    detection = None",
      "    fallback = None",
      "    for candidate in candidates:",
      "        info = detect_wordpress_info(candidate, config)",
      "        if fallback is None:",
      "            fallback = info",
      "        if info.is_wordpress and info.version:",
      "            root = candidate",
      "            detection = info",
      "            break",
      "    detection = detection if detection is not None else fallback",
      "    if root is not None:",
      "        Path('" + PY_VERIFY_ROOT_PATH + "').write_text(str(root), encoding='utf-8')",
      "finally:",
      "    sys.stdout = saved_stdout",
      "json.dumps({",
      "    'extracted_count': len(extracted),",
      "    'root': str(root) if root is not None else None,",
      "    'version': detection.version if detection is not None else None,",
      "    'locale': detection.locale if detection is not None else None,",
      "    'is_wordpress': bool(detection.is_wordpress) if detection is not None else False,",
      "    'errors': list(detection.errors) if detection is not None else [],",
      "    'limitations': list(detection.limitations) if detection is not None else []",
      "}, default=str)"
    ]).join("\n");
  }

  /**
   * Python code executed after the browser fetched the official checksums. The
   * upstream core_verify.verify_core() implementation performs the whole
   * comparison; it normally downloads the checksum list with urllib, so the
   * browser fetch is injected at the urlopen boundary and the original
   * function is restored afterwards. The vendored upstream code is not
   * modified. The upstream hashing helper writes progress notes to stdout, so
   * stdout is redirected while the comparison runs to keep the payload clean.
   */
  function buildCoreVerifyCode() {
    return pythonCoreConfigLines().concat([
      "import dataclasses, io, json, sys, urllib.error, urllib.request",
      "from pathlib import Path",
      "from wp_forensics.core_verify import verify_core",
      "checksums_path = Path('" + PY_CHECKSUMS_PATH + "')",
      "error_path = Path('" + PY_VERIFY_ERROR_PATH + "')",
      "root_path = Path('" + PY_VERIFY_DIR + "')",
      "root_file = Path('" + PY_VERIFY_ROOT_PATH + "')",
      "if root_file.exists():",
      "    root_path = Path(root_file.read_text(encoding='utf-8').strip())",
      "payload = b''",
      "error_reason = None",
      "if error_path.exists():",
      "    error_reason = error_path.read_text(encoding='utf-8').strip()",
      "elif checksums_path.exists():",
      "    payload = checksums_path.read_bytes()",
      "else:",
      "    error_reason = 'No checksums payload was provided by the browser fetch.'",
      "class _BrowserChecksumResponse:",
      "    def __init__(self, data):",
      "        self._data = data",
      "        self._pos = 0",
      "        self.length = len(data)",
      "    def read(self, size=-1):",
      "        if size is None or size < 0:",
      "            chunk = self._data[self._pos:]",
      "            self._pos = len(self._data)",
      "            return chunk",
      "        chunk = self._data[self._pos:self._pos + size]",
      "        self._pos += len(chunk)",
      "        return chunk",
      "    def __enter__(self):",
      "        return self",
      "    def __exit__(self, *exc_info):",
      "        return False",
      "def _browser_urlopen(request, *args, **kwargs):",
      "    if error_reason is not None:",
      "        raise urllib.error.URLError(error_reason)",
      "    return _BrowserChecksumResponse(payload)",
      "saved_urlopen = urllib.request.urlopen",
      "urllib.request.urlopen = _browser_urlopen",
      "saved_stdout = sys.stdout",
      "sys.stdout = io.StringIO()",
      "try:",
      "    verification = verify_core(root_path, config)",
      "finally:",
      "    sys.stdout = saved_stdout",
      "    urllib.request.urlopen = saved_urlopen",
      "json.dumps(dataclasses.asdict(verification), default=str)"
    ]).join("\n");
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function badge(text, className) {
    return el("span", "badge " + className, text);
  }

  function yesNoBadge(value, yesClass, noClass) {
    return value ? badge("Yes", yesClass) : badge("No", noClass);
  }

  function renderInspection(data) {
    resultsSection.style.display = "block";

    var strictSymlinkCount = Number(data.strict_symlink_count || 0);
    var effectiveSafe = data.is_safe_to_extract === true && strictSymlinkCount === 0;

    summaryGrid.textContent = "";
    var items = [
      [String(data.total_entries === undefined ? 0 : data.total_entries), "Entries"],
      [formatBytes(data.total_uncompressed_bytes), "Uncompressed"],
      [formatBytes(data.total_compressed_bytes), "Compressed"],
      [effectiveSafe ? "Yes" : "No", "Safe to Extract"],
      [String(strictSymlinkCount), "Symlink Entries"],
      [String((data.errors || []).length), "Errors"]
    ];
    items.forEach(function (item) {
      var box = el("div", "summary-item");
      box.appendChild(el("span", "count", item[0]));
      box.appendChild(el("span", "label", item[1]));
      summaryGrid.appendChild(box);
    });

    entriesBody.textContent = "";
    var entries = data.entries || [];
    entries.forEach(function (entry) {
      var row = document.createElement("tr");

      var nameCell = el("td", "path");
      nameCell.appendChild(el("div", null, entry.name));
      if (entry.normalized_name && entry.normalized_name !== entry.name) {
        nameCell.appendChild(el("div", "sub", "normalized: " + entry.normalized_name));
      }
      row.appendChild(nameCell);

      row.appendChild(el("td", null, formatBytes(entry.file_size)));
      row.appendChild(el("td", null, formatBytes(entry.compressed_size)));

      var strictSymlink = entry.strict_symlink === true;
      var effectiveEntrySafe = entry.is_safe_to_extract === true && !strictSymlink;

      var safeCell = document.createElement("td");
      safeCell.appendChild(badge(effectiveEntrySafe ? "Yes" : "No", effectiveEntrySafe ? "safe" : "unsafe"));
      row.appendChild(safeCell);

      var symlinkCell = document.createElement("td");
      symlinkCell.appendChild(yesNoBadge(strictSymlink || entry.is_symlink === true, "unsafe", "neutral"));
      row.appendChild(symlinkCell);

      var traversalCell = document.createElement("td");
      traversalCell.appendChild(yesNoBadge(entry.is_traversal_risk, "unsafe", "neutral"));
      row.appendChild(traversalCell);

      var duplicateCell = document.createElement("td");
      duplicateCell.appendChild(yesNoBadge(entry.is_duplicate, "warn", "neutral"));
      row.appendChild(duplicateCell);

      var statusCell = document.createElement("td");
      if (entry.error) {
        statusCell.appendChild(badge("Rejected", "unsafe"));
        statusCell.appendChild(el("div", "sub", entry.error));
      } else if (strictSymlink) {
        statusCell.appendChild(badge("Rejected", "unsafe"));
        statusCell.appendChild(el("div", "sub", "Symlink entry (strict S_IFLNK type-bit check)"));
      } else if (entry.is_safe_to_extract) {
        statusCell.appendChild(badge("OK", "safe"));
      } else {
        statusCell.appendChild(badge("Not extracted", "warn"));
      }
      row.appendChild(statusCell);

      entriesBody.appendChild(row);
    });

    inspectionNotes.textContent = "";
    var notes = [];
    (data.errors || []).forEach(function (message) {
      notes.push({ text: message, className: "unsafe" });
    });
    (data.limitations || []).forEach(function (message) {
      notes.push({ text: message, className: "warn" });
    });
    if (notes.length) {
      var list = el("ul", "notes");
      notes.forEach(function (note) {
        var item = document.createElement("li");
        item.appendChild(badge(note.className === "unsafe" ? "Error" : "Note", note.className));
        item.appendChild(el("span", "sub", " " + note.text));
        list.appendChild(item);
      });
      inspectionNotes.appendChild(list);
    }
  }

  function severityClass(severity) {
    var key = String(severity || "").toLowerCase();
    if (key === "critical" || key === "high" || key === "medium" || key === "low") return key;
    return "neutral";
  }

  function renderScanResults(scan, extractedCount) {
    scanSection.style.display = "block";

    var findings = scan.findings || [];
    var bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach(function (finding) {
      var key = String(finding.severity || "").toLowerCase();
      if (Object.prototype.hasOwnProperty.call(bySeverity, key)) bySeverity[key] += 1;
    });

    scanSummary.textContent = "";
    var items = [
      [String(scan.file_count === undefined ? 0 : scan.file_count), "Files Scanned"],
      [String(findings.length), "Findings"],
      [String(bySeverity.critical), "Critical"],
      [String(bySeverity.high), "High"],
      [String(bySeverity.medium), "Medium"],
      [String(bySeverity.low), "Low"]
    ];
    items.forEach(function (item) {
      var box = el("div", "summary-item");
      box.appendChild(el("span", "count", item[0]));
      box.appendChild(el("span", "label", item[1]));
      scanSummary.appendChild(box);
    });

    findingsBody.textContent = "";
    findings.forEach(function (finding) {
      var row = document.createElement("tr");

      var severityCell = document.createElement("td");
      severityCell.appendChild(badge(String(finding.severity || "").toUpperCase(), severityClass(finding.severity)));
      row.appendChild(severityCell);

      row.appendChild(el("td", null, finding.confidence || "-"));

      row.appendChild(el("td", null, finding.category || "-"));

      var indicatorCell = document.createElement("td");
      indicatorCell.appendChild(el("div", null, finding.indicator || "-"));
      if (finding.explanation) {
        indicatorCell.appendChild(el("div", "sub", finding.explanation));
      }
      row.appendChild(indicatorCell);

      row.appendChild(el("td", "path", finding.file_path || "-"));
      row.appendChild(el("td", null,
        (finding.line_number === null || finding.line_number === undefined) ? "-" : String(finding.line_number)));
      row.appendChild(el("td", "path", finding.evidence || "-"));

      findingsBody.appendChild(row);
    });

    scanNotes.textContent = "";
    var notes = [];
    (scan.errors || []).forEach(function (message) {
      notes.push({ text: message, className: "warn" });
    });
    (scan.limitations || []).forEach(function (message) {
      notes.push({ text: message, className: "warn" });
    });
    if (notes.length) {
      var list = el("ul", "notes");
      notes.forEach(function (note) {
        var item = document.createElement("li");
        item.appendChild(badge("Note", note.className));
        item.appendChild(el("span", "sub", " " + note.text));
        list.appendChild(item);
      });
      scanNotes.appendChild(list);
    }
    scanNotes.appendChild(el("p", "note",
      "Extracted " + extractedCount + " file(s) into a temporary in-memory directory that was deleted after the scan. " +
      "No file was executed and nothing left the browser."));
  }

  function renderScanBlocked(reasons) {
    scanSection.style.display = "block";

    scanSummary.textContent = "";
    var box = el("div", "summary-item");
    box.appendChild(el("span", "count", "Blocked"));
    box.appendChild(el("span", "label", "Extraction Refused"));
    scanSummary.appendChild(box);

    findingsBody.textContent = "";
    scanNotes.textContent = "";
    var list = el("ul", "notes");
    (reasons || []).forEach(function (reason) {
      var item = document.createElement("li");
      item.appendChild(badge("Blocked", "unsafe"));
      item.appendChild(el("span", "sub", " " + reason));
      list.appendChild(item);
    });
    scanNotes.appendChild(list);
    scanNotes.appendChild(el("p", "note", "No file was extracted and nothing was scanned."));
  }

  /**
   * Remove the uploaded archive and any extracted files from the in-memory
   * filesystem. Called after every run, including failed runs.
   */
  function cleanupFilesystem() {
    if (!pyodide) return;
    try {
      pyodide.FS.unlink(PY_ARCHIVE_PATH);
    } catch (e) {
      // Nothing to remove.
    }
    try {
      pyodide.FS.rmdir(PY_SCAN_DIR, { recursive: true });
    } catch (e) {
      // Nothing to remove.
    }
  }

  /**
   * Remove the comparison archives and the extracted snapshot directories from
   * the in-memory filesystem. Called after every comparison run, including
   * failed runs.
   */
  function cleanupCompareFilesystem() {
    if (!pyodide) return;
    [PY_ARCHIVE_PATH, PY_COMPARE_A_PATH, PY_COMPARE_B_PATH].forEach(function (path) {
      try {
        pyodide.FS.unlink(path);
      } catch (e) {
        // Nothing to remove.
      }
    });
    [PY_COMPARE_A_DIR, PY_COMPARE_B_DIR].forEach(function (dir) {
      try {
        pyodide.FS.rmdir(dir, { recursive: true });
      } catch (e) {
        // Nothing to remove.
      }
    });
  }

  function clearComparisonResults() {
    comparisonResult = null;
    if (compareResultsSection) compareResultsSection.style.display = "none";
    if (compareSummary) compareSummary.textContent = "";
    if (compareEntriesBody) compareEntriesBody.textContent = "";
    if (compareNotes) compareNotes.textContent = "";
    if (downloadCompareJsonBtn) downloadCompareJsonBtn.disabled = true;
  }

  function updateCompareState() {
    if (compareBtn) {
      compareBtn.disabled = !(compareFileA && compareFileB) || busy;
    }
    if (downloadCompareJsonBtn) {
      downloadCompareJsonBtn.disabled = !comparisonResult;
    }
  }

  /**
   * Accept one of the two snapshot archives. The same upload limits as the
   * single-archive scan apply to both snapshots.
   */
  function acceptCompareFile(slot, file) {
    if (!file) return;

    var info = slot === "a" ? compareAInfo : compareBInfo;
    var label = slot === "a" ? "Snapshot A" : "Snapshot B";

    if (!isZipFile(file)) {
      if (info) info.textContent = "No file selected";
      if (slot === "a") compareFileA = null; else compareFileB = null;
      clearComparisonResults();
      updateCompareState();
      showStatus(
        label + ": that file is not a ZIP archive. Choose a .zip file, such as a WordPress backup archive.",
        "danger"
      );
      return;
    }

    if (file.size > ZIP_SAFETY.maxCompressedSize) {
      if (info) info.textContent = "No file selected";
      if (slot === "a") compareFileA = null; else compareFileB = null;
      clearComparisonResults();
      updateCompareState();
      showStatus(
        label + ": archive is " + formatBytes(file.size) + ", above the " +
        formatBytes(ZIP_SAFETY.maxCompressedSize) + " upload limit. Nothing was read or extracted.",
        "danger"
      );
      return;
    }

    if (slot === "a") compareFileA = file; else compareFileB = file;
    if (info) info.textContent = file.name + " (" + formatBytes(file.size) + ")";
    clearComparisonResults();
    updateCompareState();
    showStatus(
      label + " accepted (" + formatBytes(file.size) + "). It has not been extracted or read yet.",
      "info"
    );
    initEngine();
  }

  function setupCompareUpload(areaId, inputId, slot) {
    var area = document.getElementById(areaId);
    var input = document.getElementById(inputId);
    if (!area || !input) return;

    area.addEventListener("click", function (event) {
      // The inner label already opens the file dialog; ignore it here so the
      // picker is not triggered twice.
      if (event.target && event.target.closest && event.target.closest("label, input")) return;
      input.click();
    });

    area.addEventListener("keydown", function (event) {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        input.click();
      }
    });

    area.addEventListener("dragover", function (event) {
      event.preventDefault();
      area.classList.add("dragover");
    });

    area.addEventListener("dragleave", function () {
      area.classList.remove("dragover");
    });

    area.addEventListener("drop", function (event) {
      event.preventDefault();
      area.classList.remove("dragover");
      var files = event.dataTransfer && event.dataTransfer.files;
      if (files && files.length) {
        acceptCompareFile(slot, files[0]);
      }
    });

    input.addEventListener("change", function (event) {
      var files = event.target.files;
      if (files && files.length) {
        acceptCompareFile(slot, files[0]);
      }
    });
  }

  /**
   * Run the shared inspection gate for one archive. The archive is staged on
   * the path the existing gate code inspects; nothing is extracted here.
   */
  async function runCompareGate(archivePath) {
    pyodide.FS.writeFile(PY_ARCHIVE_PATH, pyodide.FS.readFile(archivePath));
    var gateOutput = await pyodide.runPythonAsync(buildGateCode());
    return JSON.parse(String(gateOutput));
  }

  function comparisonStatusClass(status) {
    var key = String(status || "").toLowerCase();
    if (key === "added") return "info";
    if (key === "removed") return "unsafe";
    if (key === "modified") return "warn";
    return "neutral";
  }

  function renderComparisonBlocked(gateA, gateB) {
    if (!compareResultsSection) return;
    compareResultsSection.style.display = "block";

    compareSummary.textContent = "";
    var box = el("div", "summary-item");
    box.appendChild(el("span", "count", "Blocked"));
    box.appendChild(el("span", "label", "Extraction Refused"));
    compareSummary.appendChild(box);

    compareEntriesBody.textContent = "";
    compareNotes.textContent = "";
    var list = el("ul", "notes");
    [["Snapshot A", gateA], ["Snapshot B", gateB]].forEach(function (pair) {
      var item = document.createElement("li");
      item.appendChild(badge(pair[0], pair[1].blocked ? "unsafe" : "safe"));
      if (pair[1].blocked) {
        item.appendChild(el("span", "sub", " " + (pair[1].reasons || []).join("; ")));
      } else {
        item.appendChild(el("span", "sub", " passed the safety checks"));
      }
      list.appendChild(item);
    });
    compareNotes.appendChild(list);
    compareNotes.appendChild(el("p", "note",
      "No archive was extracted and no file was compared."));
  }

  function renderComparison(comparison, extracted) {
    if (!compareResultsSection) return;
    compareResultsSection.style.display = "block";

    var items = [
      [String(comparison.added_count || 0), "Added"],
      [String(comparison.removed_count || 0), "Removed"],
      [String(comparison.modified_count || 0), "Modified"],
      [String(comparison.unchanged_count || 0), "Unchanged"]
    ];
    compareSummary.textContent = "";
    items.forEach(function (item) {
      var box = el("div", "summary-item");
      box.appendChild(el("span", "count", item[0]));
      box.appendChild(el("span", "label", item[1]));
      compareSummary.appendChild(box);
    });

    var order = { added: 0, removed: 1, modified: 2, unchanged: 3 };
    var entries = (comparison.entries || []).slice().sort(function (a, b) {
      var keyA = String(a.status || "").toLowerCase();
      var keyB = String(b.status || "").toLowerCase();
      var rankA = Object.prototype.hasOwnProperty.call(order, keyA) ? order[keyA] : 9;
      var rankB = Object.prototype.hasOwnProperty.call(order, keyB) ? order[keyB] : 9;
      if (rankA !== rankB) return rankA - rankB;
      return String(a.path || "").localeCompare(String(b.path || ""));
    });

    compareEntriesBody.textContent = "";
    entries.forEach(function (entry) {
      var row = document.createElement("tr");

      var statusCell = document.createElement("td");
      statusCell.appendChild(badge(String(entry.status || "").toUpperCase(), comparisonStatusClass(entry.status)));
      row.appendChild(statusCell);

      row.appendChild(el("td", "path", entry.path || "-"));
      row.appendChild(el("td", "path", entry.source_hash || "-"));
      row.appendChild(el("td", "path", entry.dest_hash || "-"));

      compareEntriesBody.appendChild(row);
    });

    compareNotes.textContent = "";
    var notes = [];
    (comparison.limitations || []).forEach(function (message) {
      notes.push(message);
    });
    if (notes.length) {
      var list = el("ul", "notes");
      notes.forEach(function (text) {
        var item = document.createElement("li");
        item.appendChild(badge("Note", "warn"));
        item.appendChild(el("span", "sub", " " + text));
        list.appendChild(item);
      });
      compareNotes.appendChild(list);
    }
    compareNotes.appendChild(el("p", "note",
      "Snapshot A contributed " + (extracted.extracted_a || 0) + " extracted file(s) and Snapshot B " +
      (extracted.extracted_b || 0) + ". Files are matched by relative path and SHA-256 hash. " +
      "Both archives were read inside the browser, deleted afterwards, and no file was executed."));
  }

  /**
   * Fetch the official WordPress.org checksums in the browser. The Python
   * runtime inside the page has no network access, so the request is made
   * here and the response is handed to the upstream implementation afterwards.
   * Only the version and the locale are sent; no file, path, or hash of the
   * uploaded archive is involved.
   */
  async function fetchOfficialChecksums(version, locale) {
    var versionText = String(version || "");
    if (!/^\d+\.\d+(\.\d+)?(-[a-zA-Z0-9]+)?$/.test(versionText)) {
      return { error: "The detected version string is not a valid WordPress version, so no checksums were requested." };
    }

    var query = "version=" + encodeURIComponent(versionText);
    var localeText = String(locale || "");
    if (localeText && /^[a-z]{2,3}_[A-Z]{2,3}(_[a-z]+)?$/.test(localeText)) {
      query += "&locale=" + encodeURIComponent(localeText);
    }

    var url = CORE_VERIFY.apiUrl + "?" + query;
    var controller = null;
    var timer = null;

    try {
      if (typeof AbortController === "function") {
        controller = new AbortController();
        timer = setTimeout(function () {
          controller.abort();
        }, CORE_VERIFY.requestTimeoutSeconds * 1000);
      }

      var response = await fetch(url, controller ? { signal: controller.signal } : undefined);
      if (!response.ok) {
        return {
          error: "HTTP error " + response.status + ": the WordPress.org checksum service did not return a checksum list."
        };
      }

      var declared = response.headers && response.headers.get ? response.headers.get("content-length") : null;
      if (declared && Number(declared) > CORE_VERIFY.maxResponseBytes) {
        return { error: "The checksum response is larger than the " + CORE_VERIFY.maxResponseBytes + " byte limit and was discarded." };
      }

      var text = await response.text();
      if (new TextEncoder().encode(text).length > CORE_VERIFY.maxResponseBytes) {
        return { error: "The checksum response is larger than the " + CORE_VERIFY.maxResponseBytes + " byte limit and was discarded." };
      }

      var parsed;
      try {
        parsed = JSON.parse(text);
      } catch (parseError) {
        return { error: "The checksum response was not valid JSON and was discarded." };
      }
      if (!parsed || typeof parsed.checksums !== "object" || parsed.checksums === null) {
        return { error: "The checksum response did not contain a checksum list and was discarded." };
      }

      return { text: text };
    } catch (err) {
      return {
        error: "The official checksums could not be fetched from api.wordpress.org: " + errorMessage(err)
      };
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  function verificationStatusLabel(status) {
    var labels = {
      "verified": "Core files match the official checksums",
      "mismatches_found": "Modified core files found",
      "missing_files": "Missing core files found",
      "network_error": "Official checksums could not be retrieved",
      "unsupported_version": "Unsupported WordPress version",
      "version_not_detected": "WordPress version not detected",
      "incomplete": "Verification incomplete"
    };
    var key = String(status || "").toLowerCase();
    return labels[key] || String(status || "Unknown status");
  }

  function verificationStatusClass(status) {
    var key = String(status || "").toLowerCase();
    if (key === "verified") return "safe";
    if (key === "mismatches_found" || key === "network_error") return "unsafe";
    if (key === "missing_files" || key === "incomplete" ||
        key === "version_not_detected" || key === "unsupported_version") return "warn";
    return "neutral";
  }

  function fileVerificationStatusClass(status) {
    var key = String(status || "").toLowerCase();
    if (key === "match") return "safe";
    if (key === "mismatch") return "unsafe";
    if (key === "missing") return "warn";
    return "neutral";
  }

  function clearCoreVerifyResults() {
    if (!verifySection) return;
    verifySection.style.display = "none";
    if (verifySummary) verifySummary.textContent = "";
    if (verifyFilesBody) verifyFilesBody.textContent = "";
    if (verifyNotes) verifyNotes.textContent = "";
  }

  /**
   * Render the upstream VerificationResult. Only files that did not match are
   * listed; every value is written with textContent.
   */
  function renderCoreVerification(verification) {
    if (!verifySection) return;
    verifySection.style.display = "block";

    var files = verification.files || [];
    var problems = files.filter(function (file) {
      return String(file.status || "").toLowerCase() !== "match";
    });

    verifySummary.textContent = "";
    var items = [
      [String(verification.verified_matches || 0), "Matched"],
      [String(verification.mismatches || 0), "Mismatched"],
      [String(verification.missing || 0), "Missing"],
      [String(verification.unchecked || 0), "Unchecked"],
      [String(files.length), "Core Files Listed"],
      [String(verification.version || "-"), "Detected Version"]
    ];
    items.forEach(function (item) {
      var box = el("div", "summary-item");
      box.appendChild(el("span", "count", item[0]));
      box.appendChild(el("span", "label", item[1]));
      verifySummary.appendChild(box);
    });

    verifyFilesBody.textContent = "";
    var listed = problems.slice(0, CORE_VERIFY.maxListedFiles);
    listed.forEach(function (file) {
      var row = document.createElement("tr");
      row.appendChild(el("td", "path", file.path || "-"));

      var statusCell = document.createElement("td");
      statusCell.appendChild(badge(String(file.status || "").toUpperCase(), fileVerificationStatusClass(file.status)));
      row.appendChild(statusCell);

      row.appendChild(el("td", "path", file.expected_hash || "-"));
      row.appendChild(el("td", "path", file.actual_hash || "-"));

      verifyFilesBody.appendChild(row);
    });

    if (!listed.length) {
      var emptyRow = document.createElement("tr");
      var emptyCell = el("td", null, files.length
        ? "Every listed core file matched the official checksum."
        : "No core file was compared.");
      emptyCell.colSpan = 4;
      emptyRow.appendChild(emptyCell);
      verifyFilesBody.appendChild(emptyRow);
    }

    verifyNotes.textContent = "";
    if (verification.error) {
      var list = el("ul", "notes");
      var item = document.createElement("li");
      item.appendChild(badge("Error", "unsafe"));
      item.appendChild(el("span", "sub", " " + verification.error));
      list.appendChild(item);
      verifyNotes.appendChild(list);
    }

    var statusLine = el("p", "note");
    statusLine.textContent =
      "Result: " + verificationStatusLabel(verification.status) + ". Official checksums were requested for " +
      "WordPress " + (verification.version || "unknown version") +
      (verification.locale ? " (" + verification.locale + ")" : "") + ".";
    verifyNotes.appendChild(statusLine);

    if (problems.length > listed.length) {
      verifyNotes.appendChild(el("p", "note",
        problems.length + " file(s) did not match; only the first " + listed.length + " are listed on screen."));
    }

    verifyNotes.appendChild(el("p", "note",
      "Partial browser-based verification: only the files listed in the official WordPress.org checksum set for " +
      "this version and locale were compared. Plugins, themes, uploads, wp-content, and every other file in the " +
      "archive were not checked, so a result without mismatches is not a proof that the installation is free of " +
      "injected code."));
    verifyNotes.appendChild(el("p", "note",
      "The archive was extracted into a temporary in-memory directory that was deleted after the verification. " +
      "Only the version and the locale were sent to api.wordpress.org. No file was executed."));
  }

  /**
   * Remove the verification archive, the extracted directory, the staged
   * checksum payload, and the helper files from the in-memory filesystem.
   * Called after every verification run, including failed runs.
   */
  function cleanupCoreVerifyFilesystem() {
    if (!pyodide) return;
    [PY_ARCHIVE_PATH, PY_CHECKSUMS_PATH, PY_VERIFY_ROOT_PATH, PY_VERIFY_ERROR_PATH].forEach(function (path) {
      try {
        pyodide.FS.unlink(path);
      } catch (e) {
        // Nothing to remove.
      }
    });
    try {
      pyodide.FS.rmdir(PY_VERIFY_DIR, { recursive: true });
    } catch (e) {
      // Nothing to remove.
    }
  }

  /**
   * Verify the extracted WordPress core files against the official
   * WordPress.org checksums. The archive passes the same safety gate as the
   * single-archive scan, the checksums are fetched by the browser, and the
   * comparison itself is done by the upstream implementation.
   */
  async function runCoreVerification() {
    if (!selectedFile || busy) return;

    hideStatus();
    busy = true;
    if (verifyBtn) {
      verifyBtn.disabled = true;
      verifyBtn.textContent = "Verifying...";
    }
    // The other archive features share the staged archive path, so they are
    // paused while the verification runs.
    inspectBtn.disabled = true;
    scanBtn.disabled = true;
    clearCoreVerifyResults();

    try {
      showStatus("Loading the local Python engine...", "info");
      await ensurePyodide();
      await ensurePackage();

      showStatus("Checking archive safety before extraction...", "info");
      var buffer = await selectedFile.arrayBuffer();
      pyodide.FS.writeFile(PY_ARCHIVE_PATH, new Uint8Array(buffer));

      var gateOutput = await pyodide.runPythonAsync(buildGateCode());
      var gate = JSON.parse(String(gateOutput));

      if (gate.blocked) {
        showStatus("Core verification refused: " + gate.reasons.join("; ") + ". Nothing was extracted.", "danger");
        return;
      }

      showStatus("Extracting locally and detecting the WordPress version...", "info");
      var detectOutput = await pyodide.runPythonAsync(buildCoreDetectCode());
      var detected = JSON.parse(String(detectOutput));

      if (!detected.version) {
        showStatus(
          "No WordPress version could be detected in the archive, so no official checksums can be requested. " +
          "The extracted files were deleted.",
          "warning"
        );
        return;
      }

      showStatus("Fetching the official WordPress.org checksums in your browser...", "info");
      var fetched = await fetchOfficialChecksums(detected.version, detected.locale);

      if (fetched.error) {
        pyodide.FS.writeFile(PY_VERIFY_ERROR_PATH, new TextEncoder().encode(fetched.error));
      } else {
        pyodide.FS.writeFile(PY_CHECKSUMS_PATH, new TextEncoder().encode(fetched.text));
      }

      showStatus("Comparing the extracted core files against the official checksums...", "info");
      var verifyOutput = await pyodide.runPythonAsync(buildCoreVerifyCode());
      var verification = JSON.parse(String(verifyOutput));

      renderCoreVerification(verification);

      var status = String(verification.status || "");
      if (status === "network_error") {
        showStatus("Core verification could not be completed: " + (verification.error || "the checksums were not retrieved."), "danger");
      } else if (verification.mismatches || verification.missing) {
        showStatus(
          "Core verification finished: " + (verification.verified_matches || 0) + " matched, " +
          (verification.mismatches || 0) + " modified, " + (verification.missing || 0) + " missing and " +
          (verification.unchecked || 0) + " unchecked core file(s).",
          "warning"
        );
      } else {
        showStatus(
          "Core verification finished: " + (verification.verified_matches || 0) + " core file(s) match the official checksums. " +
          "This is a partial check - files outside the official checksum set were not verified.",
          "success"
        );
      }
    } catch (err) {
      showStatus("Core verification failed: " + errorMessage(err), "danger");
    } finally {
      cleanupCoreVerifyFilesystem();
      busy = false;
      if (verifyBtn) {
        verifyBtn.textContent = "Verify Core";
        verifyBtn.disabled = !selectedFile;
      }
      inspectBtn.disabled = !selectedFile;
      scanBtn.disabled = !selectedFile;
      updateCompareState();
    }
  }

  /**
   * Save the comparison result as a JSON file. The text is produced by the
   * upstream report generator and is only ever placed in a Blob; it is never
   * inserted into the page.
   */
  function downloadComparisonJson() {
    if (!comparisonResult) return;

    var blob = new Blob([comparisonResult.report], { type: "application/json" });
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.href = url;
    link.download = "wp-forensics-snapshot-comparison.json";
    link.style.display = "none";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(function () {
      URL.revokeObjectURL(url);
    }, 2000);
    showStatus("Comparison JSON generated locally and saved to your device.", "success");
  }

  /**
   * Compare two snapshots. Both archives pass the same inspection gate as the
   * single-archive scan, and nothing is extracted until both of them are safe.
   */
  async function runComparison() {
    if (!compareFileA || !compareFileB || busy) return;

    busy = true;
    compareBtn.disabled = true;
    compareBtn.textContent = "Comparing...";
    clearComparisonResults();
    hideStatus();

    try {
      showStatus("Loading the local Python engine...", "info");
      await ensurePyodide();
      await ensurePackage();

      showStatus("Reading both archives into the in-memory filesystem...", "info");
      var bufferA = await compareFileA.arrayBuffer();
      var bufferB = await compareFileB.arrayBuffer();
      pyodide.FS.writeFile(PY_COMPARE_A_PATH, new Uint8Array(bufferA));
      pyodide.FS.writeFile(PY_COMPARE_B_PATH, new Uint8Array(bufferB));

      showStatus("Checking the safety of both archives before extraction...", "info");
      var gateA = await runCompareGate(PY_COMPARE_A_PATH);
      var gateB = await runCompareGate(PY_COMPARE_B_PATH);

      if (gateA.blocked || gateB.blocked) {
        renderComparisonBlocked(gateA, gateB);
        showStatus(
          "Comparison refused: at least one archive did not pass the safety checks. Nothing was extracted.",
          "danger"
        );
        return;
      }

      showStatus("Extracting both snapshots into separate in-memory directories...", "info");
      var extractOutput = await pyodide.runPythonAsync(buildCompareExtractCode());
      var extracted = JSON.parse(String(extractOutput));

      showStatus("Comparing both snapshots by SHA-256 hash...", "info");
      var compareOutput = await pyodide.runPythonAsync(buildCompareCode());
      var payload = JSON.parse(String(compareOutput));
      comparisonResult = payload;

      renderComparison(payload.comparison, extracted);
      updateCompareState();

      var comparison = payload.comparison || {};
      showStatus(
        "Comparison complete. " + (comparison.added_count || 0) + " added, " +
        (comparison.removed_count || 0) + " removed, " + (comparison.modified_count || 0) +
        " modified and " + (comparison.unchanged_count || 0) + " unchanged file(s).",
        "success"
      );
    } catch (err) {
      showStatus("Comparison failed: " + errorMessage(err), "danger");
    } finally {
      cleanupCompareFilesystem();
      busy = false;
      compareBtn.textContent = "Compare Snapshots";
      updateCompareState();
    }
  }

  async function runScan() {
    if (!selectedFile || busy) return;

    hideStatus();
    busy = true;
    scanBtn.disabled = true;
    scanBtn.textContent = "Scanning...";
    setReportAvailability(false);

    try {
      showStatus("Loading the local Python engine...", "info");
      await ensurePyodide();
      await ensurePackage();

      showStatus("Checking archive safety before extraction...", "info");
      var buffer = await selectedFile.arrayBuffer();
      pyodide.FS.writeFile(PY_ARCHIVE_PATH, new Uint8Array(buffer));

      var gateOutput = await pyodide.runPythonAsync(buildGateCode());
      var gate = JSON.parse(String(gateOutput));
      renderInspection(gate.inspection);

      if (gate.blocked) {
        renderScanBlocked(gate.reasons);
        showStatus("Archive rejected before extraction: " + gate.reasons.join("; "), "danger");
        return;
      }

      // Start from a clean scratch directory so safe_extract_zip() never meets
      // an existing target file.
      try {
        pyodide.FS.rmdir(PY_SCAN_DIR, { recursive: true });
      } catch (e) {
        // Nothing to remove.
      }

      showStatus("Extracting locally and scanning files for suspicious indicators...", "info");
      var scanOutput = await pyodide.runPythonAsync(buildScanCode());
      var payload = JSON.parse(String(scanOutput));
      renderScanResults(payload.scan, payload.extracted_count);
      setReportAvailability(true);

      var count = (payload.scan.findings || []).length;
      showStatus(
        "Scan complete. " + count + " indicator(s) found across " + (payload.scan.file_count || 0) +
        " file(s). Every finding is an indicator, not confirmed malware.",
        count ? "warning" : "success"
      );
    } catch (err) {
      showStatus("Scan failed: " + errorMessage(err), "danger");
    } finally {
      cleanupFilesystem();
      busy = false;
      scanBtn.textContent = "Scan Backup";
      scanBtn.disabled = !selectedFile;
      updateCompareState();
    }
  }

  function inspectArchive() {
    if (!selectedFile || busy) return;

    hideStatus();
    inspectBtn.disabled = true;
    inspectBtn.textContent = "Inspecting...";

    ensurePyodide()
      .then(function () {
        showStatus("Loading the local Python engine...", "info");
        return ensurePackage();
      })
      .then(function () {
        showStatus("Inspecting archive entries. Nothing is extracted and no file content is read.", "info");
        return selectedFile.arrayBuffer();
      })
      .then(function (buffer) {
        pyodide.FS.writeFile(PY_ARCHIVE_PATH, new Uint8Array(buffer));
        return pyodide.runPythonAsync(buildInspectCode());
      })
      .then(function (output) {
        var data = JSON.parse(String(output));
        renderInspection(data);
        if (data.errors && data.errors.length) {
          showStatus("Inspection completed with errors: " + data.errors.join("; "), "danger");
        } else if (data.is_safe_to_extract && !Number(data.strict_symlink_count || 0)) {
          showStatus("Archive passed all safety checks. No files were extracted or analysed.", "success");
        } else {
          showStatus("Archive contains entries that did not pass the safety checks. See the results below.", "warning");
        }
      })
      .catch(function (err) {
        showStatus("ZIP inspection failed: " + errorMessage(err), "danger");
      })
      .then(function () {
        // The archive never stays in the in-memory filesystem after inspection.
        try {
          if (pyodide) pyodide.FS.unlink(PY_ARCHIVE_PATH);
        } catch (e) {
          // Nothing to clean up.
        }
        inspectBtn.textContent = "Inspect ZIP";
        inspectBtn.disabled = !selectedFile;
      });
  }

  function setupUpload() {
    uploadArea.addEventListener("click", function (event) {
      // The inner label already opens the file dialog; ignore it here so the
      // picker is not triggered twice.
      if (event.target && event.target.closest && event.target.closest("label, input")) return;
      fileInput.click();
    });

    uploadArea.addEventListener("keydown", function (event) {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        fileInput.click();
      }
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
      var files = event.dataTransfer && event.dataTransfer.files;
      if (files && files.length) {
        acceptFile(files[0]);
      }
    });

    fileInput.addEventListener("change", function (event) {
      var files = event.target.files;
      if (files && files.length) {
        acceptFile(files[0]);
      }
    });
  }

  function clearAll() {
    resetSelection(null, null);
    clearResults();
    clearScanResults();
    clearCoreVerifyResults();
    setReportAvailability(false);
    compareFileA = null;
    compareFileB = null;
    if (compareAInfo) compareAInfo.textContent = "No file selected";
    if (compareBInfo) compareBInfo.textContent = "No file selected";
    var compareAInput = document.getElementById("compare-a-input");
    var compareBInput = document.getElementById("compare-b-input");
    if (compareAInput) compareAInput.value = "";
    if (compareBInput) compareBInput.value = "";
    clearComparisonResults();
    updateCompareState();
    hideStatus();
  }

  function reportUnexpectedError(prefix, err) {
    showStatus(prefix + ": " + errorMessage(err), "danger");
  }

  function init() {
    setupUpload();
    setupCompareUpload("compare-a-area", "compare-a-input", "a");
    setupCompareUpload("compare-b-area", "compare-b-input", "b");

    inspectBtn.addEventListener("click", inspectArchive);
    scanBtn.addEventListener("click", runScan);
    if (verifyBtn) verifyBtn.addEventListener("click", runCoreVerification);
    clearBtn.addEventListener("click", clearAll);
    downloadJsonBtn.addEventListener("click", function () { downloadReport("json"); });
    downloadHtmlBtn.addEventListener("click", function () { downloadReport("html"); });
    compareBtn.addEventListener("click", runComparison);
    downloadCompareJsonBtn.addEventListener("click", downloadComparisonJson);

    window.addEventListener("error", function (event) {
      reportUnexpectedError("Unexpected error", event && event.error ? event.error : event && event.message);
    });

    window.addEventListener("unhandledrejection", function (event) {
      reportUnexpectedError("Unexpected error", event && event.reason);
    });

    updateActionStates();
    showStatus(
      "Demo ready. Choose a backup ZIP to initialise the local engine, then run \"Inspect ZIP\". " +
      "\"Verify Core\" performs a partial check of the extracted core files against the official WordPress.org " +
      "checksums, and two archives can also be compared in the snapshot comparison panel below.",
      "info"
    );
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
