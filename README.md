# DScanner - CTF Drupal Exploit Tool

DScanner 3.0.0 - Made By Taylor Christian Newsome

Overview

DScanner is an exhaustive Drupal vulnerability scanner and exploitation tool built for Capture The Flag (CTF) competitions, such as DEFCON. It targets Drupal CMS with a massive payload library covering every known vulnerability up to March 2025, plus generic web and CTF-specific attack vectors. Designed to outshine tools like Drupwn, DScanner is stealthy, fast, and packed with features to help you find flags and win challenges.

Features

Comprehensive vulnerability scanning: Includes all Drupal CVEs, SA-CORE advisories, and module-specific exploits up to March 2025.
Massive payload library: SQLi, XSS, RCE, LFI/RFI, XXE, SSRF, CSRF, file uploads, deserialization, command injection, path traversal, open redirect, session/auth bypass, and CTF flag hunting.
Stealth capabilities: Randomized user agents (including curl/wget), proxy support, and variable delays.
Multi-threaded scanning: Fast execution with up to 15 concurrent workers.
Detailed logging: Forensic analysis in dscanner.log.
SSL/TLS checks: Detects weak protocols.
CLI interface: Supports -u/--url and -h/--help options.
CTF-ready: Hunts for flags in common locations (e.g., flag.txt, .hidden/).

Installation

Clone the repository: git clone https://github.com/ClumsyLulz/DScanner.git cd DScanner
Install dependencies: pip install -r requirements.txt
Make executable (Linux/Mac): chmod +x DScanner.py
Optional - Install as command (Linux/Mac): sudo cp DScanner.py /usr/local/bin/DScanner sudo chmod +x /usr/local/bin/DScanner

Requirements

Python 3.6+
requests>=2.28.1
beautifulsoup4>=4.11.1
urllib3>=1.26.12
See requirements.txt for details.

Usage

Run with URL
DScanner -u http://target.com

Interactive mode
DScanner
(Enter URL when prompted)

Help
DScanner -h
or
DScanner --help

Example Output
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

Payloads

Drupalgeddon series (CVE-2014-3704, SA-CORE-2018-002, SA-CORE-2018-004)
SQL Injection: Basic, blind, union, error-based, out-of-band
XSS: Basic, SVG, event handlers, polyglots, filter bypasses
RCE: PHP eval, base64, file writes, shells, Twig exploits
LFI/RFI: Basic, null byte, filter streams, encoded
XXE: File disclosure, network, blind
SSRF: Localhost, file, AWS metadata, gopher
CSRF: Logout, admin creation
File Upload: PHP shells, double extensions, null byte
Deserialization: PHP objects, base64 variants
Command Injection: Basic, pipes, encoded, blind
Path Traversal: Unix, Windows, encoded
Open Redirect: Basic, encoded
Session/Auth: Hijacking, bypass, cookie tampering
CTF-Specific: Flag hunting (flag.txt, .hidden/, backup/)
Legal Notice

DScanner is for educational and authorized testing purposes only, such as DEFCON CTF. Unauthorized use against systems you do not own or have permission to test is illegal. Use responsibly.

Contributing

Fork the repo, submit pull requests, or open issues at https://github.com/ClumsyLulz/DScanner/. All contributions welcome!

Contact

GitHub: https://github.com/ClumsyLulz/
Author: Taylor Christian Newsome
