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
2. **About Me** — Professional focus on web application security, VAPT, authorized penetration testing, and WordPress security
3. **Projects & Tools** — Open-source security tools and audits:
   - [Authentication and Access Control Audit](https://github.com/samihathecss/auth-access-control-audit)
   - [Phishing Email Analyzer](https://github.com/samihathecss/phishing-email-analyser)
   - [WordPress Migration Integrity Verifier](https://github.com/samihathecss/wp-migration-integrity-verifier)
4. **Services** — Web Application Security Assessment, Authorized VAPT, WordPress Security, WordPress Malware Removal, WordPress Migration
5. **Contact** — Fiverr and GitHub links

## File Structure

```
samihathecss.github.io-main/
├── index.html          # Main HTML structure and all sections
├── styles.css          # All styling (dark navy theme, responsive layout)
├── app.js              # Vanilla JS (navigation, scroll animations)
└── README.md           # This file
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

## Contact

- **Fiverr**: [www.fiverr.com/s/r33Kk9r](https://www.fiverr.com/s/r33Kk9r)
- **GitHub**: [github.com/samihathecss](https://github.com/samihathecss)

---

*All security testing services are conducted with explicit written authorization and within a clearly defined scope.*
