#!/usr/bin/env python3
"""Emit vrika-agent/server_api/tools_catalog/tool_catalog_docs.json (curated per-tool narratives).

Summaries distill widely cited upstream manuals (RFC-style behaviour, distro man pages,
and project-maintainer README ecosystems). Run from repo root:

  python3 agent/scripts/build_tool_catalog_docs.py

"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_AGENT = _REPO / "vrika-agent"
if str(_AGENT) not in sys.path:
    sys.path.insert(0, str(_AGENT))

import tool_catalog_doc_clusters as _cdc


def _repo_root() -> Path:
    return _REPO


def _load_params_help() -> dict[str, dict[str, str]]:
    p = _repo_root() / "vrika-agent" / "server_api" / "tools_catalog" / "param_key_help.json"
    raw = json.loads(p.read_text(encoding="utf-8"))
    return {k: {"help": str(v.get("help") or "").strip()} for k, v in raw.items()}


def _summarize_param(key: str, pk: dict[str, dict[str, str]]) -> str:
    h = pk.get(key, {}).get("help", "")
    if not h:
        return ""
    sentence = h.split(". ")[0].strip().rstrip(".")
    if len(sentence) > 220:
        sentence = sentence[:217].rstrip() + "…"
    return sentence


def _param_appendix(tool: str, meta: dict, pk: dict[str, dict[str, str]]) -> str:
    params = list((meta.get("params") or {}).keys())
    optional = list((meta.get("optional") or {}).keys())
    lines = [
        "Vrika mechanics: send a JSON POST from the Execute modal—the agent drops empty optional scalars before invoking NyxStrike.",
        "Prefer explicit catalogue fields (`target`, `url`, `wordlist`, etc.) before `additional_args`; extra tokens must still match the "
        "packaged wrapper behaviour and your engagement rules.",
    ]
    req_bits = [_summarize_param(k, pk) for k in params]
    req_bits = [f"- `{k}` (required): {t}." for k, t in zip(params, req_bits) if t]
    opt_pick = optional[:18]
    if len(optional) > 18:
        remainder = len(optional) - 18
        note = f"- _(and {remainder} more optional keys — see catalogue defaults in the Execute modal)._"
    else:
        note = ""
    opt_bits = [_summarize_param(k, pk) for k in opt_pick]
    opt_lines = [f"- `{k}` (optional): {t}." for k, t in zip(opt_pick, opt_bits) if t]
    lines.extend(req_bits[:12])
    if len(req_bits) > 12:
        lines.append(f"- _(Additional required composite fields omitted for brevity — refer to catalogue.)_")
    lines.extend(opt_lines)
    if note:
        lines.append(note)
    if tool == "shuffledns":
        lines.append("- shuffleDNS fronts MassDNS-compatible jobs; tighten `resolver`/`trusted_resolver` when testing split-horizon DNS.")
    elif tool == "massdns":
        lines.append("- MassDNS emits huge DNS traffic — limit `resolve_count`, `threads`, or input size on shared links.")
    elif tool == "msfconsole":
        lines.append("- `options` should mirror Metasploit `set` pairs; payloads execute only on sanctioned lab hosts.")
    lines.insert(2, "Per-field catalogue hints (first sentence of modal help):")
    return "\n".join(lines)


def _usage_lines(tool: str, meta: dict, pk: dict[str, dict[str, str]]) -> str:
    ep = str(meta.get("endpoint") or "")
    cluster = _cdc.clustered_usage(tool, ep).rstrip()
    appendix = _param_appendix(tool, meta, pk).rstrip()
    return f"{cluster}\n\n{appendix}"


def _category_note(cat: str) -> str | None:
    riders = {
        "wifi_pentest": "Wireless probing and injection are lawful only on spectrum and networks you control by license or contract.",
        "exploitation": "Weaponised modules may crash services—snapshot lab VMs and segregate egress before launching.",
        "brute_force": "Credential guesses can trigger lockouts; coordinate with SOC and honour throttling mandates.",
        "web_vuln": "Active payloads may corrupt data stores—replay only seeded test accounts created for the drill.",
        "network_recon": "Port scanners and handshake grabbers alert defenders—mirror scope IPs exactly as authorised.",
        "intelligence": "Automated chaining still needs data-handling approvals for anything beyond public banners.",
        "ai_assist": "LLMs may retain pasted evidence—sanitize transcripts before analysis.",
        "vulnerability_intelligence": "Upstream intel feeds carry redistribution constraints—respect vendor terms internally.",
        "forensics": "Evidence images may contain regulated data—encrypt at rest immediately after extraction.",
        "active_directory": "Domain queries leave authentication telemetry—prefer dedicated assessment accounts.",
        "database": "Database credentials in JSON propagate to bastion logs—rotate after tabletop exercises.",
        "lateral_movement": "Impacket-style executions alter security event logs—isolate jump hosts and minimise shared credentials.",
        "cloud": "Cloud API tokens authenticate broad actions—purge keys after tabletop exercises.",
        "api": "API fuzzing can trigger costly side-effects (email, billing, writes)—narrow scope before unattended runs.",
        "fingerprint": "Fingerprinting correlates artefacts—sanitize exports when customer metadata is classified.",
        "binary": "Binary tooling may invoke malware safeguards—sandbox untrusted specimens.",
        "web_scan": "Broad web scanners overwhelm fragile apps—coordinate throttles before production-facing tests.",
        "monitoring": "Monitoring hooks can impact performance—isolate capture windows.",
    }
    return riders.get(cat)


def curated_long(tool: str, desc: str) -> str:
    """Upstream-focused synopsis (manual/README knowledge, no citations)."""
    d = desc.rstrip(".").strip()
    match tool:
        case "ai_analyze_session":
            body = (
                "Vrika workflow intelligence posts stored session artefacts to an LLM for summarisation, correlation, "
                "and remediation hints without re-running scanners."
            )
        case "vulnx":
            body = (
                "CVE-oriented vulnerability intelligence aggregator that correlates CVE metadata, exploits, references, "
                "and remediation notes for triage—not a substitute for vendor PSIRT advisories."
            )
        case "waymore":
            body = (
                "waymore automates crawling multiple web archives (including Wayback and partner mirrors) "
                "to resurrect historical URLs and HTTP responses tied to OSINT pivots."
            )
        case "analyze-target":
            body = (
                "Vrika Intelligent Decision Engine compiles fingerprints, exposures, and heuristics for a scoped target "
                "to seed manual validation and chaining tasks."
            )
        case "create-attack-chain" | "preview-attack-chain":
            body = (
                "Planner service that derives ordered attack hypotheses from analysed signals; preview mode avoids persistence "
                "while creation mode persists structured chains for assisted operations."
            )
        case "smart-scan":
            body = (
                "Smart-scan orchestrates multiple catalogue tools with AI-assisted parameter selection, parallel fan-out, "
                "and guardrails limited by `max_tools` and enterprise policy."
            )
        case "technology-detection":
            body = (
                "Technology stack inference pass that maps observed banners, HTML, and TLS clues to testing guidance for later manual steps."
            )
        case "nmap":
            body = (
                "Nmap (Network Mapper) is the open-source scanner for host discovery, TCP/UDP probing, service fingerprinting, "
                "and Nmap Scripting Engine checks; results label ports as open, closed, or filtered per Nmap’s state machine."
            )
        case "nmap_advanced":
            body = (
                "Advanced Nmap profile exposes scripted scan types (`-sS`, UDP blends), granular timing templates, selectable NSE script lists, "
                "optional OS/version detection bundles, stealth toggles, and passthrough CLI fragments."
            )
        case "masscan":
            body = (
                "Masscan is Robert Graham’s asynchronous SYN scanner designed for sweeping very large nets quickly by issuing raw packets "
                "with an isolated userspace TCP stack—rate-limit explicitly because it stresses upstream transit."
            )
        case "rustscan":
            body = (
                "Rustscan is an extremely fast preliminary port enumerator that optionally hands results to downstream Nmap for deeper fingerprinting "
                "(batch size/timeouts materially affect responsiveness on busy segments)."
            )
        case "enum4linux":
            body = (
                "Classic Perl aggregator around Samba tooling that enumerates SMB/RPC users, shares, groups, transports, policies, "
                "and brute-force-able RIDs analogous to legacy Windows enum.exe output."
            )
        case "enum4linux-ng":
            body = (
                "enum4linux-ng modernises Rid cycling, Kerberos interplay, regex-friendly JSON summaries, "
                "and granular toggles covering users, shares, groups, policies, etc."
            )
        case "smbmap":
            body = (
                "smbmap lists SMB shares, permissions, and common misconfigurations with optional command execution primitives where creds permit."
            )
        case "arp-scan":
            body = (
                "arp-scan issues ARP who-has probes on Ethernet segments—ideal for authoritative L2 inventories but intrusive on noisy LAN fabrics."
            )
        case "gobuster":
            body = (
                "Gobuster (OJ Reeves) brute-forces directory, DNS, and virtual-host names at high concurrency using deterministic HTTP status/size heuristics."
            )
        case "ffuf":
            body = (
                "ffuf (Fuzz Faster U Fool) substitutes the `FUZZ` keyword across verbs, routes, headers, and bodies enabling multi-slot fuzz workflows."
            )
        case "feroxbuster":
            body = (
                "feroxbuster is a recursive Rust content discovery crawler that honours depth semantics, concurrency controls, "
                "and response heuristics without manual script glue."
            )
        case "katana":
            body = (
                "ProjectDiscovery’s katana crawler streams JS-aware navigation graphs for attack-surface inventories and pipeline-friendly URL emission."
            )
        case "gospider":
            body = (
                "GoSpider walks sites, parses robots.txt and sitemap.xml, leverages Burp/OSINT feeders, proxies, concurrency controls, and optional JS sources "
                "for sprawling endpoint discovery jobs."
            )
        case "httpx":
            body = (
                "httpx is ProjectDiscovery’s fast HTTP probing engine that fingerprints live hosts and optional technologies/status/title artefacts."
            )
        case "hurl":
            body = (
                "hurl (Tom Hudson) exposes encoding gymnastics—decode/encode payloads across hex/url/base64 and related transforms supporting web abuse testing."
            )
        case "testssl":
            body = (
                "testssl.sh is a LibreSSL/OpenSSL-heavy TLS auditor enumerating cipher suites, certificate issues, known weaknesses, "
                "and downgrade vectors without needing a heavyweight GUI harness."
            )
        case "dirsearch":
            body = (
                "dirsearch multithreads extension-aware directory busting using advanced filters, blacklist rules, recursion, "
                "and customised wordlists favoured in modern web assessments."
            )
        case "wafw00f":
            body = (
                "wafw00f fingerprints web application firewall products by provoking characteristic block pages and heuristic signatures."
            )
        case "wpscan":
            body = (
                "WPScan targets WordPress installations by enumerating users, outdated plugins/themes, Interesting Files, CVE references, "
                "and brute-force safeguards aware of canonical WordPress internals."
            )
        case "joomscan":
            body = (
                "Joomla-specific vulnerability scanner inspecting core/components for known exploits and configuration weaknesses."
            )
        case "interactsh":
            body = (
                "Interactsh (ProjectDiscovery) issues correlation tokens for out-of-band detection of SSRF/DNS/blind SSRF behaviours via hosted or self-hosted brokers."
            )
        case "nuclei":
            body = (
                "Nuclei is ProjectDiscovery’s template DSL runner that executes YAML-defined checks spanning HTTP/TCP/cloud/file protocols "
                "with clustered execution and granular severity/tag filters."
            )
        case "nikto":
            body = (
                "Nikto is a long-standing CGI/web server auditor that hunts dangerous files, insecure headers, risky methods, outdated software fingerprints, "
                "and canned misconfiguration patterns."
            )
        case "sqlmap":
            body = (
                "sqlmap automates detecting and exploiting classic SQL injection classes (union, blind, stacked, time-based) across dozens of DBMS engines "
                "with granular tamper and data extraction features."
            )
        case "dalfox":
            body = (
                "DalFox focuses on reflected/stored XSS by mining parameters, injecting polyglot payloads, and optionally pairing with collaborator servers for blind XSS."
            )
        case "xsser":
            body = (
                "XSSer assembles vectored XSS attacks with GUI/automation primitives, crawler hooks, statistical reporting, "
                "and heuristic payload sets aligned with OWASP classifications."
            )
        case "dotdotpwn":
            body = (
                "DotDotPwn traverses traversal fuzzing payloads across protocols (HTTP/FTP/etc.) referencing historic canonical traversal patterns "
                "for identifying path normalisation flaws."
            )
        case "jaeles":
            body = (
                "Jaeles is a YAML-signature oriented web vuln hunter emphasising customised templates and baseline diffing akin to miniature nuclei clones."
            )
        case "commix":
            body = (
                "commix hunts OS command injection and shell interaction vectors via staged injection levels and tamper primitives similar to sqlmap philosophies."
            )
        case "msfvenom":
            body = (
                "Metasploit’s msfvenom stages encoded payloads targeting multiple architectures and transports (reverse/bind meterpreter, staged/unstaged) "
                "with selectable output formats (`elf`, `exe`, `msi`, scripting languages)."
            )
        case "hydra":
            body = (
                "Hydra is the parallel login cracker spanning dozens of services (SMB, SSH, HTTP forms, databases) combining dictionary, "
                "brute, and configurable module-specific options."
            )
        case "hashcat":
            body = (
                "hashcat is the predominant GPU-assisted hash recovery suite supporting hundreds of modes (straight, combinators, masks, hybrid rules) "
                "with tuning flags for workstation thermals."
            )
        case "john":
            body = (
                "John the Ripper is the canonical CPU-centric password security auditor with `-format` selectors, incremental modes, external filters, "
                "and incremental GPU helpers via forks."
            )
        case "medusa" | "patator":
            body = (
                "Modular login brute-force frameworks—Medusa stresses parallel transports while Patator unifies dictionaries across SMB, SSH, HTTP, etc., "
                "with Pythonic verbosity controls."
            )
        case "ophcrack":
            body = (
                "Ophcrack loads rainbow tables optimised for speedy LM/NTLM hash lookups when suitable table packs exist on-disk."
            )
        case "hashid":
            body = (
                "hashid heuristically scores hash formats to suggest candidate algorithms before feeding hashcat/john pipelines."
            )
        case "ldapdomaindump":
            body = (
                "ldapdomaindump pulls LDAP-visible AD objects—users, groups, computers, policies—ideal for foothold inventories when LDAP binds succeed."
            )
        case "impacket-scripts":
            body = (
                "Thin wrapper invoking arbitrary SecureAuth/impacket utilities with script names plus target/options strings mirroring upstream CLI ergonomics."
            )
        case "impacket-spec":
            body = (
                "Inspection helper retrieving argument specifications for Impacket scripts so planners can hydrate JSON payloads safely prior to invocation."
            )
        case "impacket-ad-enum":
            body = (
                "Curated Impacket façade for enumeration scripts (`GetNPUsers`, `FindDelegation`, `lookupsid`, etc.) exposing DC IP, hashes, AES keys, Kerberos booleans "
                "and guarded `extra_*` escapes."
            )
        case "impacket-remote-exec":
            body = (
                "Curated façade for lateral movement transports (`wmiexec`, `psexec`, `atexec`) with command strings, UNC shares, shells, hashes, AES keys "
                "and impersonation safeguards."
            )
        case "parsero":
            body = (
                "Parsero parses `robots.txt` directives to resurrect hidden paths that operators attempted to withhold from benign crawlers."
            )
        case "whois":
            body = (
                "whois retrieves registrar/registry data revealing abuse contacts, name servers, and routing artefacts for IPs or domains "
                "depending on registrar coverage."
            )
        case "http-headers":
            body = (
                "Lightweight HTTPS/HTTP HEAD fetcher akin to curl’s `-sI`, surfacing CSP/HSTS/feature-policy signals for quick header reviews."
            )
        case "dig":
            body = (
                "Uses ISC BIND dig semantics (`+short` style) for deterministic DNS answers across multiple RR types configurable via `record_types`."
            )
        case "amass":
            body = (
                "OWASP Amass orchestrates recursive DNS brute, API-backed OSINT, graph storage, ASN intel, wildcard detection, "
                "and scripted modules described in upstream user guides/config formats."
            )
        case "subfinder":
            body = (
                "Subfinder merges dozens of passive API/certificate/OSINT connectors for subdomain discovery with sane rate limits controlled via feature flags "
                "(e.g., `silent`, `all_sources`)."
            )
        case "assetfinder":
            body = (
                "Tomnomnom’s passive subdomain enumerator combining certificate transparency, reverse DNS scraping, "
                "and brute toggles respecting `only_subdomains` filters."
            )
        case "shuffledns":
            body = (
                "ProjectDiscovery shuffleDNS wraps MassDNS-compatible resolution with wildcard detection, brute wordlists, "
                "trusted resolvers, and JSON-friendly reporting."
            )
        case "massdns":
            body = (
                "MassDNS is a staggeringly fast resolver stub issuing millions of iterative queries with socket fan-out knobs, hashing heuristics, "
                "and optional drop-privilege controls—keep resolvers sane."
            )
        case "sublist3r":
            body = (
                "Sublist3r aggregates search-engine and OSINT subdomain hints with tuneable parallelism per engine selections."
            )
        case "fierce":
            body = (
                "fierce automates recursive DNS brute with zone-transfer attempts, traversal options, "
                "and heuristic domain walking described in canonical DNS penetration references."
            )
        case "dnsenum":
            body = (
                "dnsenum threads zone transfers, brute-force guesses, wildcard detection, reverse lookups, "
                "and WHOIS-guided pivoting reminiscent of Perl-era DNS auditors."
            )
        case "gau":
            body = (
                "getallurls (tomnomnom/link discovery) merges AlienVault Open Threat Exchange, FDNS, Archive, Common Crawl snapshots "
                "for historical URL inventories."
            )
        case "waybackurls":
            body = (
                "waybackurls (tomnommom) specialises in streaming Wayback Machine endpoints for archival URL mining."
            )
        case "theHarvester":
            body = (
                "theHarvester harvests emails, hosts, IPs, ASN metadata from search engines/APIs aligning with passive intel tradecraft."
            )
        case "eaphammer":
            body = (
                "EAPHammer stages rogue WPA/WPA2-Enterprise portals, credential relays, karma attacks, captive-portal payloads, "
                "negotiation attacks, and cert plumbing for controlled WPA-EAP lab assessments."
            )
        case "aircrack-ng":
            body = (
                "aircrack-ng leverages dictionary attacks plus statistical tests against WPA handshakes inside captures; optional BSSID filters reduce noise "
                "when multiple APs coexist."
            )
        case "airmon-ng":
            body = (
                "airmon-ng manages monitor-mode lifecycle for Aircrack suites (checks interfering processes and toggles vap interfaces)."
            )
        case "airodump-ng":
            body = (
                "airodump-ng passively observes 802.11 beacons/data frames, pinning channels/BSSIDs/clients writing rolling PCAP prefixes."
            )
        case "aireplay-ng":
            body = (
                "aireplay-ng injects forged frames (`deauth`, `fakeauth`, ARP replay) with controlled burst counts respecting physical-layer risks."
            )
        case "airbase-ng":
            body = (
                "airbase-ng fabricates soft access points impersonating BSSIDs/channel plans for sanctioned evil-twin playbook labs."
            )
        case "airdecap-ng":
            body = (
                "airdecap-ng decrypts WEP/WPA packets once PSK/passphrases or WEP keys are known for offline evidence review."
            )
        case "hcxdumptool":
            body = (
                "hcxdumptool captures PMKID/EAPOL frames from modern chipsets with filter lists, driver-specific attack bitmaps "
                "and PCAPNG exporters aligned with hcxtools ecosystems."
            )
        case "hcxpcapngtool":
            body = (
                "hcxpcapngtool converts captures into hash formats consumable by hashcat/john WPA cracking workflows."
            )
        case "wifite":
            body = (
                "wifite orchestrates WPA/WEP attack playbooks chaining airmon/aircrack/reaver bully flows with guided prompts—still demands RF discipline."
            )
        case "mdk4":
            body = (
                "MDK4 is a frame injection destructor testing AP/client resilience (`deauth`, `beacon flood`, ESSIDs) strictly for cages you control."
            )
        case "bettercap":
            body = (
                "bettercap is a Go-based MITM platform with modular caplets integrating Wi‑Fi/AP impersonation, "
                "BLE attacks, scripting, BLE/Wi‑Fi coexistence primitives on monitor interfaces."
            )
        case "checksec":
            body = (
                "checksec (PaX/grsecurity heritage) parses ELF security mitigations (`NX`, `RELRO`, `PIE`, `Canary`, fortify)."
            )
        case "binwalk":
            body = (
                "binwalk signature-scans blobs for filesystems/firmware manifests and optionally extracts cascaded components for reverse engineering pipelines."
            )
        case "strings":
            body = (
                "GNU/strings surfaces printable sequences aiding triage inside firmware dumps or unstructured binaries."
            )
        case "ropgadget":
            body = (
                "ROPgadget enumerates syscall/gadget inventories with filters for arches and instruction constraints."
            )
        case "radare2":
            body = (
                "radare2 is the scriptable reversing framework supporting multi-arch disassembly/visual modes with batch `-c` command strings."
            )
        case "pacu":
            body = (
                "Pacu is RhinoSecurity’s modular AWS exploitation post-exploitation framework tracking keys, IAM abuse, snapshots, buckets, persistence, "
                "and enumerated service metadata under named sessions."
            )
        case "cloudmapper":
            body = (
                "Cloudmapper visualises IAM/network relationships in AWS accounts (prepare/webserver/reporting actions) to spot privilege sprawl."
            )
        case "prowler":
            body = (
                "Prowler automates hundreds of AWS/Azure/GCP checks across CIS benchmarks, incident response playbooks, custom profiles, "
                "and compliance reporting exports."
            )
        case "trivy":
            body = (
                "Aqua Trivy scans container images, IaC, Kubernetes manifests, or filesystems for CVEs and misconfigurations with severity filters."
            )
        case "kube-hunter":
            body = (
                "kube-hunter actively/passively probes Kubernetes clusters for attack paths (exposed dashboards, kubelet APIs, "
                "mis-scoped service accounts) per upstream hunter modules."
            )
        case "bbot":
            body = (
                "BBot (Black Lantern Security) is a modular OSINT + attack-surface engine accepting rich YAML/JSON `parameters` seeds for safe pipeline automation."
            )
        case "angr":
            body = (
                "angr provides symbolic execution, symbolic states, CFG recovery, and interactive solving APIs over binaries with optional inline Python drivers."
            )
        case "ghidra":
            body = (
                "Ghidra headless mode imports specimens, runs analysis passes, optional scripts, and exports project artefacts for CI-scale reverse engineering."
            )
        case "objdump":
            body = (
                "GNU objdump disassembles object files/ELFs with optional intel syntax toggles and architecture-specific views."
            )
        case "one-gadget":
            body = (
                "one_gadget scans libc builds for single-instruction `execve(/bin/sh)` pivots using leakable constraints."
            )
        case "ropper":
            body = (
                "Ropper enumerates ROP/JOP gadgets with quality scoring, arch awareness, and search filters."
            )
        case "libc-database":
            body = (
                "libc-database matches leaked symbol offsets to packaged libc builds for exploit reliability on remote targets."
            )
        case "xxd":
            body = (
                "xxd hex-dumps or reverts dumps with offset/length controls mirroring util-linux behaviour."
            )
        case "autopsy":
            body = (
                "Autopsy/SleuthKit GUI workflows carve timelines, keyword indices, and extracted files from forensic disk images."
            )
        case "gdb":
            body = (
                "GNU gdb debugs userland binaries with command macros, optional command files, and scripted breakpoint automation."
            )
        case "pwntools":
            body = (
                "pwntools supplies tube abstractions, ROP builders, ELF parsing, and exploit scaffolding executed from `script_content` against local/remote targets."
            )
        case "pwninit":
            body = (
                "pwninit patches CTF binaries with supplied libc/ld pairs and emits starter exploit templates reducing manual linking drudgery."
            )
        case "dirb":
            body = (
                "DIRB brute-forces web paths usingclassic wordlists and optional fine-grained HTTP codes mirroring circa-2000 scanners still common in engagements."
            )
        case "hakrawler":
            body = (
                "hakrawler rapidly enumerates reachable links/endpoints respecting depth/forms/robots/sitemap/optional Wayback supplementation."
            )
        case "autorecon":
            body = (
                "AutoRecon chains service discovery/port scans/scripted modules with pacing (`heartbeat`), timeout safeguards, configurable output dirs, "
                "and additional_args bridging custom modules."
            )
        case "wfuzz":
            body = (
                "Wfuzz multiplexes payloads into HTTP verbs/headers/parameters with advanced filters analogous to Burp Intruder ergonomics."
            )
        case "graphql-scanner":
            body = (
                "Dedicated GraphQL assessor probing introspection, depth-based DoS motifs, abusive mutations, "
                "and insecure resolver exposure within scope."
            )
        case "jwt-analyzer":
            body = (
                "JWT tooling that decodes JOSE blobs, hunts `alg=none`, tests RS→HS swaps, brute-forces weak secrets "
                "and correlates forged tokens via optional target URLs."
            )
        case "api-schema-analyzer":
            body = (
                "Static reviewer for Swagger/OpenAPI/GraphQL schemas spotting weak auth scopes, dangerously broad operations, SSRF-able callbacks, "
                "and data-exposure regressions prior to fuzzing."
            )
        case "arjun":
            body = (
                "Arjun heuristically enumerates latent HTTP GET/POST/JSON/XML parameters referencing wordlists "
                "`delay`, `threads`, stabilisation switches, plus passthrough fragments."
            )
        case "paramspider":
            body = (
                "ParamSpider correlates archival sources to enumerate parameters per domain respecting depth/recursion/exclusion lists."
            )
        case "x8":
            body = (
                "x8 diffs baseline vs candidate parameter responses to spotlight hidden reflective parameters with optional body/header contexts."
            )
        case "qsreplace":
            body = (
                "qsreplace rewrites URL query fragments with placeholder tokens prepping ffuf/ffuf-compatible pipelines "
                "(often `replacement=FUZZ`)."
            )
        case "anew":
            body = (
                "anew streams STDIN uniqueness into optional output sinks—canonical dedupe glue for massive URL lists."
            )
        case "uro":
            body = (
                "uro trims URL lists removing noisy duplicates with optional blacklist/whitelist filters."
            )
        case "nbtscan":
            body = (
                "nbtscan issues NetBIOS status probes across LAN segments spotting Windows hosts revealing names/workgroups swiftly."
            )
        case "rpcclient":
            body = (
                "rpcclient (Samba) issues MS-RPC calls (`enumdomusers`, `querydominfo`) using inline command macros."
            )
        case "responder":
            body = (
                "Responder poisons broadcast name-resolution protocols harvesting challenge responses,"
                "optionally spoofing WPAD, performing traffic analysis loops, configurable durations—keep off production VLANs."
            )
        case "volatility":
            body = (
                "Volatility 2-classic exposes hundreds of forensic plugins for parsing Windows/Linux/macOS RAM dumps conditioned on memory profiles "
                "matching KDBG signatures."
            )
        case "foremost":
            body = (
                "foremost carves predefined file types via header/footer heuristics from raw images akin to DD dumps."
            )
        case "steghide":
            body = (
                "steghide embeds AES/zip-compressed payloads in lossless carriers with passphrase-controlled integrity checks "
                "`action` selects embed/extract/info flows."
            )
        case "exiftool":
            body = (
                "exiftool reads/writes EXIF/IPTC/XMP tags across multimedia formats aiding metadata leak reviews."
            )
        case "hashpump":
            body = (
                "hashpump automates MD5/SHA length-extension forgeries crafting signatures over attacker-controlled suffixes (`append_data`)."
            )
        case "scout-suite":
            body = (
                "Scout Suite audits AWS/Azure/GCP/OCI footprints with hierarchical HTML reports, selectable services, curated exceptions "
                "and profile-aware authentication."
            )
        case "clair":
            body = (
                "Clair static-scans layered container images referencing vulnerability databases/APIs configurable via YAML `config` blobs."
            )
        case "docker-bench-security":
            body = (
                "Docker bench implements CIS Docker host guidance checks selectively via `checks`/`exclude` lists."
            )
        case "checkov":
            body = (
                "Bridgecrew Checkov statically analyses IaC repos (Terraform, CloudFormation, K8s) with granular control ids and output SARIF integrations."
            )
        case "terrascan":
            body = (
                "Terrascan applies vendor policy packs (`policy_type`), severity thresholds, IaC scanning mode toggles spanning Terraform/Kubernetes registries etc."
            )
        case "kube-bench":
            body = (
                "kube-bench executes CIS Kubernetes benchmark checks constrained by kubeconfig targets/version hints/config directories."
            )
        case "falco":
            body = (
                "Falco hooks syscalls emitting JSON/SHELL alerts for container breakout signals with optional ephemeral capture windows (`duration`)."
            )
        case "nxc":
            body = (
                "NetExec (classic CrackMapExec descendant) abstracts SMB/WinRM/LDAP/MSSQL post-explo modules with cohesive cred handling."
            )
        case "evil-winrm":
            body = (
                "Evil-WinRM supplies Ruby-based WinRM shells with pass-the-hash, logging, AMSI-ish toggles, and script execution aides."
            )
        case "msfconsole":
            body = (
                "Metasploit console automation accepts module paths plus option dictionaries aligning with canonical `use`, `set`, `run` flows."
            )
        case "searchsploit":
            body = (
                "searchsploit queries local Exploit-DB mirrors for textual matches aligning with responsibly disclosed disclosures."
            )
        case "whatweb":
            body = (
                "WhatWeb applies thousands of fingerprints to HTTP stacks discovering CMS/CDN/email addresses quickly."
            )
        case "burpsuite":
            body = (
                "Vrika proxies to a packaged Burp-like automation façade performing scoped spidering/passive-active scans with concurrency caps (`max_pages`)."
            )
        case "zaproxy":
            body = (
                "OWASP ZAP automation configures baseline/full scans against `target`, API listener ports, keyed automation (`api_key`), "
                "`scan_type`, and exporters."
            )
        case "http-framework":
            body = (
                "HTTP-framework route mimics scripted curl/httpie ergonomics exposing verbs, payloads, cookie jars, replay actions for manual assertions."
            )
        case "api_fuzzer":
            body = (
                "High-level REST fuzz mapper combining `base_url`, HTTP verbs, wordlists and explicit endpoint manifests for brute enumeration."
            )
        case "schemathesis":
            body = (
                "Schemathesis derives property tests from OpenAPI/GraphQL definitions with phased execution, concurrency, rate limiting, timeouts, reporting "
                "`checks` aligning with Hypothesis integrations."
            )
        case "sherlock":
            body = (
                "Sherlock enumerates pseudonyms across hundreds of exposed social sites flagging dormant or hijackable personas."
            )
        case "recon-ng":
            body = (
                "Recon-ng is a modular CLI recon framework injecting marketplace modules seeded by authoritative domains (`modules`)."
            )
        case "maltego":
            body = (
                "Maltego remote transforms pivot OSINT graphs—supply target seeds plus transform descriptors compatible with investigator editions."
            )
        case "spiderfoot":
            body = (
                "Spiderfoot orchestrates modular OSINT sweeps (>200 connectors) emitting correlation graphs correlating artefacts for a seeded `target`."
            )
        case "hashcat-utils":
            body = (
                "hashcat-utils bundle specialised CPU helpers (candidate generators, cutters) prepping inputs for downstream hash cracking."
            )
        case "vol":
            body = (
                "Volatility3 (`vol`) rewrites memory forensics with pythonic plugin architecture differing from volatility2 semantics—supply plugin slugs/templates."
            )
        case "photorec":
            body = (
                "PhotoRec file carver rebuilds artefacts ignoring filesystem metadata—paired with selectable file families."
            )
        case "testdisk":
            body = (
                "TestDisk recovers partitions/boot sectors and undeletes files referencing interactive CLI flows automated here."
            )
        case "scalpel":
            body = (
                "Scalpel carves configurable file types guided by forensic header/footer definitions akin to foremost."
            )
        case "bulk_extractor":
            body = (
                "bulk_extractor parallel-scans forensic images extracting emails URLs credit cards keyed by selectable scanner modules."
            )
        case "stegsolve":
            body = (
                "Stegsolve visual-analyses bitmap planes aiding manual LSB/permutation stego detection for CTF/lab artefacts."
            )
        case "zsteg":
            body = (
                "zsteg detects PNG/BMP/APNG anomalies (zlib/LSB/comment abuse) favoured in layered CTF payloads."
            )
        case "outguess":
            body = (
                "Outguess classic JPEG redundancy-channel steganography embed/extractor with iterative statistical refinements."
            )
        case "file":
            body = (
                "libmagic `file` fingerprints binary types/magic descriptors ahead of toolchain-specific unpacking."
            )
        case "sleuthkit":
            body = (
                "SleuthKit CLI primitives (`blkls`, `icat`, `fls`) ingest forensic images for scripted evidence plumbing."
            )
        case "wireshark":
            body = (
                "Wireshark/tshark PCAP analysis supports capture filters/display filters scripted operations—mind privacy."
            )
        case "tshark":
            body = (
                "tshark is Wireshark’s text mode exposing decoding pipelines, `-T` exporters, scripting (`-z`) stats for automation."
            )
        case "tcpdump":
            body = (
                "tcpdump records libpcap expressions with BER-length filters—coordinate before tapping sensitive VLANs."
            )
        case "kismet":
            body = (
                "kismet passively observes multi-protocol wireless frames with logging/IDS components on supported NICs;"
                "coordinate spectrum licensing."
            )
        case "mysql":
            body = (
                "mysql/mariadb CLI connector runs scoped SQL probes—prefer least-privilege DB users and terminate TLS tunnels per vendor guidance."
            )
        case "sqlite3":
            body = (
                "SQLite evaluator executes examiner `.schema`/`.read` flows against forensic databases without networked listeners."
            )
        case _:
            body = (
                f"{d}. Consult upstream README/man-page coverage shipped with NyxStrike for exhaustive flags — Vrika exposes this route "
                "so validated JSON avoids opaque unmanaged shell quoting."
            )
    return body


def _core_safety() -> str:
    return (
        "Operate only inside authorized penetration tests or sanctioned lab networks. Respect stop conditions, lawful intercept "
        "rules, and internal change windows. Sensitive parameters are captured in Vrika tenant execution logs alongside "
        "NyxStrike response snippets — avoid pasting production secrets when alternatives exist."
    )


def assemble_tool_bundle(name: str, meta: dict[str, object], pk: dict[str, dict[str, str]]) -> dict[str, str]:
    desc = str(meta.get("desc") or "").strip()
    cat = str(meta.get("category") or "uncategorized")
    ep = str(meta.get("endpoint") or "")
    rider = _category_note(cat)
    safety = _core_safety()
    if rider:
        safety = f"{safety} {rider}"
    extra = _cdc.safety_appendix(name)
    if extra:
        safety = f"{safety} {extra}"
    lead = curated_long(name, desc)
    long_desc = _cdc.compose_long_description(lead, name, cat, ep)
    return {
        "long_description": long_desc,
        "usage": _usage_lines(name, meta, pk),
        "safety": safety,
    }


def main() -> None:
    repo = _repo_root()
    sys.path.insert(0, str(repo / "vrika-agent"))
    import tool_registry as tr

    pk = _load_params_help()
    bundles = {n: assemble_tool_bundle(n, tr.TOOLS[n], pk) for n in sorted(tr.TOOLS.keys())}
    out = repo / "vrika-agent" / "server_api" / "tools_catalog" / "tool_catalog_docs.json"
    out.write_text(json.dumps(bundles, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {out} ({len(bundles)} tools)")


if __name__ == "__main__":
    main()

