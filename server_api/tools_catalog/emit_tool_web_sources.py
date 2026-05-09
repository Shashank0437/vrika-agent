#!/usr/bin/env python3
"""Build tool_web_sources.json from curated URLs + registry-aligned summaries.

Run from repository root::

    python agent/server_api/tools_catalog/emit_tool_web_sources.py
    python agent/scripts/generate_arsenal_user_documentation.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import tool_registry as tr  # noqa: E402

# Primary docs, canonical repos, or official wikis. Empty string = NyxStrike/CipherStrike-only connector.
URLS: dict[str, str] = {
    "ai_analyze_session": "",
    "airbase-ng": "https://www.aircrack-ng.org/doku.php?id=airbase-ng",
    "aircrack-ng": "https://www.aircrack-ng.org/doku.php?id=aircrack-ng",
    "airdecap-ng": "https://www.aircrack-ng.org/doku.php?id=airdecap-ng",
    "aireplay-ng": "https://www.aircrack-ng.org/doku.php?id=aireplay-ng",
    "airmon-ng": "https://www.aircrack-ng.org/doku.php?id=airmon-ng",
    "airodump-ng": "https://www.aircrack-ng.org/doku.php?id=airodump-ng",
    "amass": "https://owasp.org/www-project-amass/",
    "analyze-target": "",
    "anew": "https://github.com/tomnomnom/anew",
    "angr": "https://docs.angr.io/",
    "api-schema-analyzer": "https://swagger.io/specification/",
    "api_fuzzer": "https://owasp.org/www-project-web-security-testing-guide/",
    "arjun": "https://github.com/s0md3v/Arjun",
    "arp-scan": "https://github.com/royhills/arp-scan",
    "assetfinder": "https://github.com/tomnomnom/assetfinder",
    "autopsy": "https://www.autopsy.com/documentation/",
    "autorecon": "https://github.com/Tib3rius/AutoRecon",
    "bbot": "https://github.com/blacklanternsecurity/bbot",
    "bettercap": "https://www.bettercap.org/",
    "binwalk": "https://github.com/ReFirmLabs/binwalk",
    "bulk_extractor": "https://github.com/simsong/bulk_extractor",
    "burpsuite": "https://portswigger.net/burp/documentation",
    "checkov": "https://www.checkov.io/",
    "checksec": "https://github.com/slimm609/checksec.sh",
    "clair": "https://quay.github.io/clair/",
    "cloudmapper": "https://github.com/duo-labs/cloudmapper",
    "commix": "https://github.com/commixproject/commix",
    "create-attack-chain": "",
    "dalfox": "https://github.com/hahwul/dalfox",
    "dig": "https://bind9.readthedocs.io/en/latest/manpages.html",
    "dirb": "https://dirb.sourceforge.net/",
    "dirsearch": "https://github.com/maurosoria/dirsearch",
    "dnsenum": "https://github.com/fwaeytens/dnsenum",
    "docker-bench-security": "https://github.com/docker/docker-bench-security",
    "dotdotpwn": "https://github.com/wireghoul/dotdotpwn",
    "eaphammer": "https://github.com/s0lst1c3/eaphammer",
    "enum4linux": "https://github.com/CiscoCXSecurity/enum4linux",
    "enum4linux-ng": "https://github.com/cddmp/enum4linux-ng",
    "evil-winrm": "https://github.com/Hackplayers/evil-winrm",
    "exiftool": "https://exiftool.org/exiftool_pod.html",
    "falco": "https://falco.org/docs/",
    "feroxbuster": "https://github.com/epi052/feroxbuster",
    "ffuf": "https://github.com/ffuf/ffuf",
    "fierce": "https://github.com/mschwager/fierce",
    "file": "https://man7.org/linux/man-pages/man1/file.1.html",
    "foremost": "https://github.com/korczis/foremost",
    "gau": "https://github.com/lc/gau",
    "gdb": "https://sourceware.org/gdb/documentation/",
    "ghidra": "https://ghidra-sre.org/CheatSheet.html",
    "gobuster": "https://github.com/OJ/gobuster",
    "gospider": "https://github.com/jaeles-project/gospider",
    "graphql-scanner": "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
    "hakrawler": "https://github.com/hakluke/hakrawler",
    "hashcat": "https://hashcat.net/wiki/",
    "hashcat-utils": "https://github.com/hashcat/hashcat-utils",
    "hashid": "https://github.com/psypanda/hashID",
    "hashpump": "https://github.com/bwall/HashPump",
    "hcxdumptool": "https://github.com/ZerBea/hcxdumptool",
    "hcxpcapngtool": "https://github.com/ZerBea/hcxtools",
    "http-framework": "https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html",
    "http-headers": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
    "httpx": "https://github.com/projectdiscovery/httpx",
    "hurl": "https://github.com/tomnomnom/hacks/tree/master/hurl",
    "hydra": "https://github.com/vanhauser-thc/thc-hydra",
    "impacket-ad-enum": "https://github.com/fortra/impacket",
    "impacket-remote-exec": "https://github.com/fortra/impacket",
    "impacket-scripts": "https://github.com/fortra/impacket",
    "impacket-spec": "https://github.com/fortra/impacket",
    "interactsh": "https://github.com/projectdiscovery/interactsh",
    "jaeles": "https://github.com/jaeles-project/jaeles",
    "john": "https://www.openwall.com/john/doc/",
    "joomscan": "https://github.com/OWASP/joomscan",
    "jwt-analyzer": "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
    "katana": "https://github.com/projectdiscovery/katana",
    "kismet": "https://www.kismetwireless.net/docs/",
    "kube-bench": "https://github.com/aquasecurity/kube-bench",
    "kube-hunter": "https://github.com/aquasecurity/kube-hunter",
    "ldapdomaindump": "https://github.com/dirkjanm/ldapdomaindump",
    "libc-database": "https://github.com/niklasb/libc-database",
    "maltego": "https://docs.maltego.com/",
    "masscan": "https://github.com/robertdavidgraham/masscan",
    "massdns": "https://github.com/blechschmidt/massdns",
    "mdk4": "https://github.com/aircrack-ng/mdk4",
    "medusa": "https://github.com/jmk-foofus/medusa",
    "msfconsole": "https://docs.metasploit.com/",
    "msfvenom": "https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html",
    "mysql": "https://dev.mysql.com/doc/refman/8.0/en/mysql.html",
    "nbtscan": "https://github.com/resurrecting-open-source-projects/nbtscan",
    "nikto": "https://github.com/sullo/nikto",
    "nmap": "https://nmap.org/book/man.html",
    "nmap_advanced": "https://nmap.org/book/man.html",
    "nuclei": "https://docs.projectdiscovery.io/tools/nuclei/",
    "nxc": "https://www.netexec.wiki/",
    "objdump": "https://sourceware.org/binutils/docs/binutils/objdump.html",
    "one-gadget": "https://github.com/david942j/one_gadget",
    "ophcrack": "https://ophcrack.sourceforge.io/",
    "outguess": "https://manpages.debian.org/bullseye/outguess/outguess.1.en.html",
    "pacu": "https://github.com/RhinoSecurityLabs/pacu",
    "paramspider": "https://github.com/devanshbatham/paramspider",
    "parsero": "https://github.com/behindthefirewall/Parsero",
    "patator": "https://github.com/lanjelot/patator",
    "photorec": "https://www.cgsecurity.org/wiki/PhotoRec",
    "preview-attack-chain": "",
    "prowler": "https://docs.prowler.com/",
    "pwninit": "https://github.com/io12/pwninit",
    "pwntools": "https://docs.pwntools.com/en/stable/",
    "qsreplace": "https://github.com/tomnomnom/qsreplace",
    "radare2": "https://book.rada.re/",
    "recon-ng": "https://github.com/lanmaster53/recon-ng",
    "responder": "https://github.com/lgandx/Responder",
    "ropgadget": "https://github.com/JonathanSalwan/ROPgadget",
    "ropper": "https://github.com/sashs/Ropper",
    "rpcclient": "https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html",
    "rustscan": "https://github.com/RustScan/RustScan",
    "scalpel": "https://github.com/sleuthkit/scalpel",
    "schemathesis": "https://schemathesis.readthedocs.io/",
    "scout-suite": "https://github.com/nccgroup/ScoutSuite",
    "searchsploit": "https://www.exploit-db.com/searchsploit",
    "sherlock": "https://github.com/sherlock-project/sherlock",
    "shuffledns": "https://github.com/projectdiscovery/shuffledns",
    "sleuthkit": "https://wiki.sleuthkit.org/",
    "smart-scan": "",
    "smbmap": "https://github.com/ShawnDEvans/smbmap",
    "spiderfoot": "https://www.spiderfoot.net/documentation/",
    "sqlite3": "https://www.sqlite.org/cli.html",
    "sqlmap": "https://github.com/sqlmapproject/sqlmap/wiki/usage",
    "steghide": "https://steghide.sourceforge.net/documentation.php",
    "stegsolve": "https://github.com/Giotino/stegsolve",
    "strings": "https://man7.org/linux/man-pages/man1/strings.1.html",
    "subfinder": "https://github.com/projectdiscovery/subfinder",
    "sublist3r": "https://github.com/aboul3la/Sublist3r",
    "tcpdump": "https://www.tcpdump.org/manpages/tcpdump.1.html",
    "technology-detection": "",
    "terrascan": "https://runterrascan.io/docs/",
    "testdisk": "https://www.cgsecurity.org/wiki/TestDisk",
    "testssl": "https://testssl.sh/",
    "theHarvester": "https://github.com/laramies/theHarvester",
    "trivy": "https://aquasecurity.github.io/trivy/",
    "tshark": "https://www.wireshark.org/docs/man-pages/tshark.html",
    "uro": "https://github.com/s0md3v/uro",
    "vol": "https://github.com/volatilityfoundation/volatility3",
    "volatility": "https://github.com/volatilityfoundation/volatility3",
    "vulnx": "https://github.com/projectdiscovery/vulnx",
    "wafw00f": "https://github.com/EnableSecurity/wafw00f",
    "waybackurls": "https://github.com/tomnomnom/waybackurls",
    "waymore": "https://github.com/xnl-h4ck3r/waymore",
    "wfuzz": "https://github.com/xmendez/wfuzz",
    "whatweb": "https://github.com/urbanadventurer/WhatWeb",
    "whois": "https://datatracker.ietf.org/doc/rfc3912/",
    "wifite": "https://github.com/kimocoder/wifite2",
    "wireshark": "https://www.wireshark.org/docs/",
    "wpscan": "https://github.com/wpscanteam/wpscan",
    "x8": "https://github.com/Sh1r0-h1g4sh1/x8",
    "xsser": "https://github.com/epsylon/xsser",
    "xxd": "https://man7.org/linux/man-pages/man1/xxd.1.html",
    "zaproxy": "https://www.zaproxy.org/docs/",
    "zsteg": "https://github.com/zed-0xff/zsteg",
}

# Deeper summaries (public docs); fall back to registry description augmentation.
RICH: dict[str, str] = {
    "nmap": (
        "Nmap discovers live hosts, open ports, services, and can run Nmap Scripting Engine checks; "
        "it is the reference implementation for sanctioned network discovery work."
    ),
    "nmap_advanced": (
        "Advanced Nmap profiles expose timing, NSE script lists, and OS/version toggles described in the Nmap Reference Guide; "
        "use them when standard presets need finer grained control."
    ),
    "nuclei": (
        "Nuclei is a fast template-driven scanner from ProjectDiscovery; YAML templates describe how to probe for "
        "misconfigurations and CVE-style issues across HTTP and many other protocols."
    ),
    "sqlmap": (
        "sqlmap automates detection and exploitation of SQL injection flaws against many DBMS backends; "
        "its wiki documents tampering, enumeration, and operational safety considerations."
    ),
    "zaproxy": (
        "OWASP ZAP is an open-source web app scanner and proxy with spidering, passive scanning, and automation APIs suitable for CI pipelines."
    ),
    "masscan": (
        "Masscan is an asynchronous Internet-scale port scanner; the README documents rate limits, output formats, and BPF usage."
    ),
    "rustscan": (
        "RustScan wraps mass-port discovery quickly then optionally hands off to Nmap for deeper enumeration, as described in its GitHub documentation."
    ),
    "ffuf": (
        "ffuf performs high-speed HTTP fuzzing for directories, virtual hosts, parameters, and verbs; refer to the repository wiki for matcher/filter flags."
    ),
    "feroxbuster": (
        "feroxbuster recursively brute forces web content with configurable concurrency; project docs cover recursion depth and status-code filters."
    ),
    "gobuster": (
        "Gobuster enumerates DNS names, virtual hosts, S3 buckets, or web paths depending on mode; the README details each subcommand."
    ),
    "httpx": (
        "httpx probes HTTP/S endpoints for alive status, technologies, titles, and metadata; ProjectDiscovery docs outline probe toggles that mirror many modal options."
    ),
    "subfinder": (
        "Subfinder passively enumerates subdomains using curated OSINT sources; documentation explains resolver tuning and source configuration."
    ),
    "amass": (
        "OWASP Amass maps external attack surfaces using intel, enum, and database subcommands with configurable data sources."
    ),
    "hashcat": (
        "hashcat is a GPU-accelerated hash recovery tool; the wiki documents attack modes, rule files, and legal expectations for offline material."
    ),
    "john": (
        "John the Ripper is a widely used password security auditing tool with extensive format support documented on openwall.com."
    ),
    "hydra": (
        "Hydra performs parallelized login brute-force attempts against numerous network services; see the project README for per-module options."
    ),
    "msfvenom": (
        "msfvenom generates Metasploit payloads and encoders; Rapid7's documentation explains payload selection, output formats, and encoding iterations."
    ),
    "msfconsole": (
        "The Metasploit Framework console drives exploit modules, auxiliary scanners, and sessions; official docs cover workspace safety and post-exploitation flows."
    ),
    "commix": (
        "commix focuses on command injection detection and exploitation; the GitHub docs list tampering and injection techniques."
    ),
    "dalfox": (
        "DalFox is a focused XSS scanner with DOM, reflected, and blind payload strategies documented in the repository."
    ),
    "nikto": (
        "Nikto is a web server scanner that checks for dangerous files, outdated versions, and server misconfigurations."
    ),
    "wafw00f": (
        "wafw00f fingerprints web application firewalls by sending provocation requests and interpreting responses."
    ),
    "testssl": (
        "testssl.sh evaluates TLS/SSL ciphers, protocols, and common weaknesses locally over sockets without relying on third-party test sites."
    ),
    "volatility": (
        "The Volatility 3 framework analyses memory dumps with pluggable modules for processes, networking, and malware artefacts."
    ),
    "vol": (
        "This entry mirrors the Volatility memory forensics workflow for analyst shortcuts; module names follow upstream Volatility 3 documentation."
    ),
    "radare2": (
        "radare2 is a scriptable reversing environment with disassembly, debugging, and binary analysis features documented in the official radare book."
    ),
    "angr": (
        "angr performs symbolic execution, CFG recovery, and automated reasoning over binaries; the academic-style docs explain analyses and pitfalls."
    ),
    "burpsuite": (
        "Burp Suite is PortSwigger's integrated web testing toolkit covering proxy, scanning, and sequencing features via docs.portswigger.net."
    ),
    "trivy": (
        "Trivy scans container images, IaC, and filesystems for CVEs and misconfigurations; Aqua Security's documentation details scanners and severities."
    ),
    "prowler": (
        "Prowler automates compliance and security checks across AWS, Azure, and GCP APIs with configurable check lists."
    ),
    "checkov": (
        "Checkov scans Infrastructure-as-Code for policy violations across Terraform, CloudFormation, Kubernetes manifests, and more."
    ),
    "terrascan": (
        "Terrascan detects IaC misconfigurations across multiple providers using OPA-backed policies."
    ),
    "nxc": (
        "NetExec (nxc) is the community successor to CrackMapExec for coercing, spraying, and executing against network services; the wiki documents protocols and OPSEC notes."
    ),
    "evil-winrm": (
        "Evil-WinRM provides a WinRM shell with pass-the-hash support for legitimately tested Windows estates."
    ),
    "impacket-scripts": (
        "Impacket supplies pure-Python protocol implementations for SMB, MSRPC, Kerberos, and LDAP operations used during AD assessments."
    ),
    "impacket-spec": (
        "Impacket specialty scripts expose lower-level primitives for crafting Windows protocol traffic in lab settings."
    ),
    "impacket-ad-enum": (
        "Impacket Active Directory enumeration recipes query LDAP, SAMR, and MSRPC interfaces documented across Fortra's Impacket repository."
    ),
    "impacket-remote-exec": (
        "Impacket remote execution helpers orchestrate techniques like WMI, SMB, and DCOM only where expressly authorized."
    ),
    "responder": (
        "Responder poisons LLMNR/NBT-NS/mDNS to harvest credential challenges on local segments during controlled assessments."
    ),
    "vulnx": (
        "ProjectDiscovery's vulnx (evolved from CVEmap data tooling) searches, filters, and analyses public vulnerability intelligence including CVE records."
    ),
    "waymore": (
        "waymore harvests URLs and archived HTTP responses from Wayback, Common Crawl, URLScan, and other OSINT feeds for deep recon."
    ),
    "interactsh": (
        "Interactsh provides asynchronous out-of-band interaction servers for spotting blind SSRF, XSS, and deserialization issues."
    ),
    "graphql-scanner": (
        "GraphQL testing should follow OWASP's GraphQL cheat sheet covering introspection abuse, excessive query depth, and authorization pitfalls."
    ),
    "jwt-analyzer": (
        "JWT testing aligns with OWASP JWT guidance on algorithm confusion, weak HMAC secrets, and token validation bypass patterns."
    ),
    "api-schema-analyzer": (
        "OpenAPI/Swagger definitions describe attack surface; the OpenAPI specification explains document structure for aligning schema reviews."
    ),
    "http-framework": (
        "The NyxStrike HTTP testing connector implements crafted requests, replay, and spider-style exploration analogous to manual Burp/curl workflows—pair usage with OWASP WSTG scenarios."
    ),
}


def _summary(name: str) -> str:
    meta = tr.TOOLS[name]
    desc = meta["desc"].rstrip(".")
    if name in RICH:
        return RICH[name]
    url = URLS.get(name, "")
    if not url:
        return (
            f"{desc}. This capability is implemented as a CipherStrike/NyxStrike API on the agent; "
            "refer to your tenant operator guide for request semantics beyond the registry fields."
        )
    return (
        f"{desc}. Further operational context, flags, and limitations are described in the linked upstream documentation."
    )


def main() -> None:
    missing = set(tr.TOOLS) - set(URLS)
    extra = set(URLS) - set(tr.TOOLS)
    if missing or extra:
        raise SystemExit(f"URL map out of sync: missing={sorted(missing)} extra={sorted(extra)}")
    out: dict[str, dict[str, str]] = {}
    for name in sorted(tr.TOOLS):
        out[name] = {"url": URLS[name], "summary": _summary(name)}
    path = Path(__file__).with_name("tool_web_sources.json")
    path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    weak = sorted(k for k, v in out.items() if not v["url"])
    print(f"Wrote {path} ({len(out)} tools, {len(weak)} without public URL)")


if __name__ == "__main__":
    main()
