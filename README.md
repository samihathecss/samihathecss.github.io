# Samiha Tasnim — Cybersecurity Portfolio

Cybersecurity portfolio showcasing web application security projects, security tools, and professional services.

## Website

A professional, responsive portfolio website built with **vanilla HTML, CSS, and JavaScript** — no frameworks, no build tools, no external dependencies. Designed for free hosting on GitHub Pages.

### Features

- **Modern dark navy theme** with blue accents and clean typography
- **Fully responsive** layout optimized for mobile and desktop
- **Accessible** semantic HTML5 with ARIA labels and keyboard navigation
- **Smooth scrolling** navigation with active link highlighting
- **Mobile-first** design featuring a hamburger menu toggle
- **Intersection Observer** animations for subtle section reveals
- **No third-party scripts** — all code runs locally

### Sections

1. **Hero** — Name, headline, introduction, and call-to-action buttons
2. **About Me** — Professional focus on web application security, VAPT, and WordPress security
3. **Projects & Tools** — Open-source security tools and audits:
   - [Authentication and Access Control Audit](https://github.com/samihathecss/auth-access-control-audit)
   - [Phishing Email Analyzer](https://github.com/samihathecss/phishing-email-analyser)
   - [WordPress Migration Integrity Verifier](https://github.com/samihathecss/wp-migration-integrity-verifier)
   - [WP Forensics & Recovery Assistant](https://github.com/samihathecss/wp-forensics-recovery-assistant)
   - [WP Plugin Risk & Hardening Auditor](https://github.com/samihathecss/wp-plugin-risk-hardening-auditor)
4. **Services** — Web Application Security Assessment, Authorized VAPT, WordPress Security, WordPress Malware Removal, WordPress Migration
5. **Contact** — Fiverr and GitHub links

## Live Demos

Two of the tools are also published as browser demos that run entirely in the
visitor's browser. The demos are static folders served by GitHub Pages from
this repository.

| Demo | URL | Runs |
|---|---|---|
| WP Forensics &amp; Recovery Assistant | https://samihathecss.github.io/demos/wp-forensics/ | The upstream `wp_forensics` package |
| WP Plugin Risk &amp; Hardening Auditor | https://samihathecss.github.io/demos/wp-plugin-auditor/ | The upstream `wp_plugin_auditor` package |

Both demos use [Pyodide 0.26.4](https://pyodide.org/) and
[JSZip 3.10.1](https://stuk.github.io/jszip/) and contain a verbatim copy of
the corresponding upstream Python package, so the analysis and the reports
are produced by the real project code.

**Privacy.** There is no upload endpoint and no server-side analysis. The
selected archives and PHP files are read inside the visitor's browser, the
uploaded PHP is never executed, and the temporary files are deleted after
every run. The only outbound requests are the two public CDN scripts, the
vendored Python modules served from this repository, and — in the core
integrity check only — a request to `api.wordpress.org` carrying the
WordPress version and locale.

**Limitations.** The browser demos are not the full command-line tools. The
forensics core check is partial (it compares only the files in the official
WordPress.org checksum set), and the plugin auditor uses regular-expression
heuristics rather than a PHP parser, so both can produce false positives and
false negatives. Each demo page documents its own limitations, safety limits
and the upstream commit it was vendored from.

## File Structure

```
samihathecss.github.io-main/
├── index.html          # Main HTML structure and all sections
├── styles.css          # All styling (dark navy theme, responsive layout)
├── app.js              # Vanilla JS (navigation, scroll animations)
├── README.md           # This file
└── demos/
    ├── wp-forensics/           # Browser demo of the forensics tool
    │   ├── index.html
    │   ├── app.js
    │   ├── README.md
    │   ├── VENDORED.md
    │   └── wp_forensics/       # Upstream Python package, copied verbatim
    └── wp-plugin-auditor/      # Browser demo of the plugin auditor
        ├── index.html
        ├── app.js
        ├── README.md
        ├── VENDORED.md
        └── wp_plugin_auditor/  # Upstream Python package, copied verbatim
```

## Local Preview

No build step is required. To preview locally, serve the files with a simple HTTP server:

```bash
# Python 3
python -m http.server 8000

# Node.js (if http-server is installed)
npx http-server .
```

Then open `http://localhost:8000` in your browser.

> **Note:** Opening `index.html` directly via `file://` may cause issues with the Intersection Observer animations. A local server is recommended.

## Deployment

This site is designed for **GitHub Pages** hosting:

1. Ensure all files are in the root of the `main` branch
2. In your repository settings, enable GitHub Pages from the `main` branch
3. The site will be available at `https://samihathecss.github.io/`

No configuration or build tools are needed — GitHub Pages serves static HTML, CSS, and JS directly.

The two browser demos under `demos/` are published the same way: they are
plain folders in the `main` branch, so they appear at
`https://samihathecss.github.io/demos/wp-forensics/` and
`https://samihathecss.github.io/demos/wp-plugin-auditor/` with no build step,
no server and no configuration.

## Contact

- **Fiverr**: [www.fiverr.com/s/r33Kk9r](https://www.fiverr.com/s/r33Kk9r)
- **GitHub**: [github.com/samihathecss](https://github.com/samihathecss)

---

*All security testing services are conducted with explicit written authorization and within a clearly defined scope.*
