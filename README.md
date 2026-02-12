# DScanner 3.0.0

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#license) [![Python Version](https://img.shields.io/badge/python-3.6%2B-green.svg)](#requirements) [![Last update](https://img.shields.io/badge/last--update-March%202025-orange.svg)](#note)

> **DScanner 3.0.0 — Made by Taylor Christian Newsome**

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [Usage](#usage)

   * [Run with URL (one-shot)](#run-with-url)
   * [Interactive mode](#interactive-mode)
   * [Help](#help)
6. [Example Output](#example-output)
7. [Payloads](#payloads)
8. [Detailed Logging](#detailed-logging)
9. [Legal Notice](#legal-notice)
10. [Contributing](#contributing)
11. [Contact](#contact)
12. [License](#license)
13. [Note](#note)

---

## Overview

DScanner is an exhaustive Drupal vulnerability scanner and exploitation tool built for Capture The Flag (CTF) competitions (e.g., DEFCON). It targets Drupal CMS with a massive payload library covering every known vulnerability up to **March 2025**, plus generic web and CTF-specific attack vectors.

Designed to outshine similar tools, DScanner focuses on speed, stealth, and thorough exploit coverage to help you find flags and win challenges.

**Author:** Taylor Christian Newsome

---

## Features

* **Comprehensive vulnerability scanning** — Includes Drupal CVEs, SA-CORE advisories, and module-specific exploits up to March 2025.
* **Massive payload library** — SQLi, XSS, RCE, LFI/RFI, XXE, SSRF, CSRF, file uploads, deserialization, command injection, path traversal, open redirect, session/auth bypass, and CTF flag hunting.
* **Stealth capabilities** — Randomized user agents (including curl/wget), proxy support, and variable delays to reduce fingerprinting.
* **Multi-threaded scanning** — Fast execution with up to **15 concurrent workers**.
* **Detailed logging** — Forensic analysis written to `dscanner.log`.
* **SSL/TLS checks** — Detects weak protocols and ciphers.
* **CLI interface** — Supports `-u/--url` and `-h/--help` options for automation.
* **CTF-ready** — Searches common flag locations (e.g., `flag.txt`, `.hidden/`, `backup/`).

---

## Requirements

* **Python:** 3.6+
* **Python packages (minimum):**

  * `requests>=2.28.1`
  * `beautifulsoup4>=4.11.1`
  * `urllib3>=1.26.12`

See `requirements.txt` for the complete dependency list.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/ClumsyLulz/DScanner.git
cd DScanner

# Install dependencies
pip install -r requirements.txt

# Make executable (Linux / macOS)
chmod +x DScanner.py

# Optional - Install as a system command (Linux / macOS)
sudo cp DScanner.py /usr/local/bin/DScanner
sudo chmod +x /usr/local/bin/DScanner
```

---

## Usage

### Run with URL (one-shot)

```bash
DScanner -u http://target.com
```

### Interactive mode

```bash
DScanner
# (Enter URL when prompted)
```

### Help

```bash
DScanner -h
# or
DScanner --help
```

---

## Example Output

```
Made By Taylor Christian Newsome
DScanner 3.0.0 - DEFCON CTF Drupal Exploit Monster (March 2025)

[INFO] Scanning target: http://target.com
[INFO] Detected Drupal Version: 8
[SSL] Cipher: ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
[SECURITY HEADERS]
[✓] X-Content-Type-Options: nosniff
[✗] X-Frame-Options missing
[SENSITIVE FILES]
[+] Exposed: http://target.com/sites/default/settings.php (Size: 1024 bytes)
[!!] File Exposure content detected!
[DRUPAL VULNERABILITY SCAN]
[!!] Confirmed RCE in CVE-2018-7600 (RCE): http://target.com/user/register
[EVIDENCE] Found: ['whoami']
[DRUPAL-SPECIFIC CHECKS]
[+] Drupal system block detected
```

---

## Payloads

DScanner ships with a large and diverse set of payloads and exploit techniques, including but not limited to:

* **Drupalgeddon series:** CVE-2014-3704, SA-CORE-2018-002, SA-CORE-2018-004
* **SQL Injection:** basic, blind, union, error-based, out-of-band
* **XSS:** basic, SVG, event handlers, polyglots, filter bypasses
* **RCE:** PHP `eval`, base64 payloads, file writes, reverse/interactive shells, Twig template exploits
* **LFI / RFI:** null byte, filter streams, encoded payloads
* **XXE:** file disclosure, network SSRF/XEE, blind XXE
* **SSRF:** localhost, file, cloud metadata (e.g., AWS), gopher protocol tricks
* **CSRF:** logout, admin creation, state-changing operations
* **File Upload:** PHP shells, double extension tricks, null byte bypasses
* **Deserialization:** PHP object injection, base64 encoded variants
* **Command Injection:** pipes, encoded payloads, blind injection techniques
* **Path Traversal:** Unix, Windows, encoded traversal payloads
* **Open Redirect:** basic and encoded redirect payloads
* **Session / Auth:** hijacking, bypass techniques, cookie tampering
* **CTF-Specific:** targeted flag hunting (e.g., `flag.txt`, `.hidden/`, `backup/`)

---

## Detailed Logging

All scan activity and forensic details are recorded to `dscanner.log` for later analysis and incident reconstruction.

---

## Legal Notice

**DScanner is provided for educational and authorized testing purposes only**, such as Capture The Flag events (e.g., DEFCON). Unauthorized use against systems you do not own or do not have explicit permission to test is **illegal** and strictly prohibited. By using DScanner you agree to only test targets for which you have written authorization.

---

## Contributing

Contributions are welcome. If you'd like to contribute:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add some feature"`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

Alternatively, open an issue to discuss bugs, feature requests, or improvements.

Repository: `https://github.com/ClumsyLulz/DScanner/`

---

## Contact

* **GitHub:** [https://github.com/ClumsyLulz/](https://github.com/ClumsyLulz/)
* **Author:** Taylor Christian Newsome

---

## License

This project uses the MIT License. See the `LICENSE` file for details.

---

## Note

Payloads and vulnerability coverage include advisories and exploits known up to **March 2025**. Use DScanner responsibly and only in authorized environments.
