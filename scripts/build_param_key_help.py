#!/usr/bin/env python3
"""Emit agent/server_api/tools_catalog/param_key_help.json from tool_registry keys.

Run from repo root: python3 agent/scripts/build_param_key_help.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _collect_keys() -> list[str]:
    repo = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo / "vrika-agent"))
    import tool_registry as tr  # noqa: E402

    keys: set[str] = set()
    for meta in tr.TOOLS.values():
        keys.update(meta.get("params") or {})
        keys.update(meta.get("optional") or {})
    return sorted(keys)


def _bn() -> str:
    return " Send JSON booleans true/false (Vrika modals serialize checkbox fields)."


def _help(k: str) -> str:
    kl = k.lower()

    BOOLEAN = {
        "aggressive": "When true, wrappers usually opt into intrusive bundles such as `nmap -A`; requires privileged raw sockets.",
        "all_sources": "Expand subfinder to every passive source—more external queries and latency.",
        "analyze": "Responder analyse-only posture versus active spoofing loops.",
        "attack_handshake": "Wi-Fi utilities bias toward WPA handshake harvesting when drivers allow.",
        "attack_pmkid": "Prefer PMKID capture paths on supported chipsets.",
        "auto_domain": "shuffleDNS may infer apex domains from mixed inputs—disable for strict scope.",
        "blind": "Route XSS testing through out-of-band/collaborator channels for blind sinks.",
        "busy_poll": "MassDNS trades CPU for lower latency via tight socket polling loops.",
        "debug": "Emit verbose traces (Impacket, HTTP utilities); may leak secrets into logs.",
        "disable_update_check": "Skip vendor version pings (useful air-gapped).",
        "disassemble": "Force disassembly-oriented output in objdump-style connectors.",
        "extended_input": "Allow MassDNS extended input encodings beyond bare labels.",
        "fingerprint": "Responder OS/service fingerprinting during poisoning jobs.",
        "flush": "Force MassDNS to flush partial results mid-run.",
        "follow_redirects": "HTTP helpers follow 3xx chains—watch for open-redirect scope creep.",
        "force_wpad_auth": "Force captive WPAD auth flows—only in isolated RF labs.",
        "forms": "hakrawler enumerates HTML forms in addition to anchors.",
        "headless": "Drive Burp-alternative or ZAP automation without a desktop session.",
        "https": "http-headers helper uses TLS when probing raw hostnames.",
        "include_other_source": "gospider adds optional third-party link sources.",
        "include_subs": "Include discovered subdomains in spider expansion lists.",
        "introspection": "GraphQL scanners may run introspection-assisted checks.",
        "json": "Emit JSON-line output for ShuffleDNS-compatible tooling.",
        "kerberos": "Impacket connectors use Kerberos instead of classical NTLM only.",
        "mutations": "GraphQL scanners include mutation-focused test cases.",
        "no_color": "Strip ANSI colour codes for CI logs.",
        "no_pass": "Permit credential-less binds when upstream scripts expect that sentinel.",
        "no_redirect": "Disable HTTP redirect following for deterministic responses.",
        "norecurse": "MassDNS stub mode without recursive iteration.",
        "only_subdomains": "assetfinder prints hostnames without bare apex records.",
        "os_detection": "Enable OS fingerprinting (`nmap -O`) where templates map it.",
        "other_source": "Enable optional OSINT feeds in gospider.",
        "predictable": "Deterministic MassDNS behaviour for repeatable tests.",
        "probe": "httpx runs liveness/TLS fingerprint passes.",
        "quiet": "Suppress non-error MassDNS chatter.",
        "robots": "Respect or parse robots.txt during crawls.",
        "root": "Request privileged MassDNS capabilities when the wrapper allows.",
        "sitemap": "Pull sitemap-derived URLs during crawls.",
        "stable": "Arjun stabilises differential heuristics for noisy targets.",
        "status_code": "httpx prints HTTP status codes in output tables.",
        "stealth": "Prefer quieter scan templates when mappers honour the flag.",
        "strict_wildcard": "shuffleDNS strict wildcard handling for poisoned zones.",
        "suppress": "hurl-style helpers hide decorative stdout.",
        "tech_detect": "httpx enriches results with technology fingerprints.",
        "title": "httpx captures HTML `<title>` tags alongside probes.",
        "update": "Allow tooling metadata refresh pings (shuffleDNS).",
        "use_recovery": "Impacket enables Kerberos session recovery quirks.",
        "verbose": "Extra SMB/RPC/DNS chatter for troubleshooting.",
        "verify_ip": "MassDNS verifies answers against trusted resolvers.",
        "version_detection": "Enable service/version probing (`nmap -sV`) mappings.",
        "version": "Surface `--version`-style banners when connectors expose them.",
        "wayback": "hakrawler can fold Wayback-derived URLs into the crawl frontier.",
        "wpad": "Responder answers WPAD—illegal outside sanctioned RF enclosures.",
        "sticky": "MassDNS retries stick to previously working resolver paths.",
    }
    if kl in BOOLEAN:
        return BOOLEAN[kl] + _bn()

    # Exact strings (merged semantics when one JSON key spans multiple connectors).
    SPECIFIC: dict[str, str] = {
        "session_id": "Server-side Vrika/NyxStrike session UUID/hash used to reload transcripts for LLM planners.",
        "session_name": "Pacu workspace label isolating Dynamo-style AWS attack state on the agent.",
        "target": "Primary IPv4/IPv6/hostname/CIDR or bulk newline list routed into network scanners and RPC clients.",
        "targets": "Host groups for kube-bench-style scopes or multitarget wrappers.",
        "target_bssid": "802.11 BSSID narrowed for Bettercap Wi‑Fi tooling.",
        "target_essid": "SSID string for rogue AP labs or WPA correlation workflows.",
        "target_host": "Remote host for pwntools or callback harnesses.",
        "target_port": "Remote TCP port paired with `target_host` for exploit callbacks.",
        "target_url": "Optional HTTP sink where JWT tamper harnesses replay altered tokens.",
        "target_binary": "Local binary executed by pwntools when `exploit_type` is local.",
        "domain": "Authorised DNS apex fed to Amass/subfinder/GAU style OSINT connectors.",
        "domains": "Additional apex names shuffledns can merge with `domain` for brute jobs.",
        "domainlist": "Path to newline-separated domains for MassDNS bulk resolution.",
        "url": "Fully qualified HTTP/S URL for crawlers, fuzzers, or vuln scanners (scheme required).",
        "urls": "URL batch for qsreplace, uro, or anew dedup pipelines.",
        "base_url": "API root such as `https://api.target` that relative fuzz paths expand against.",
        "endpoint": "HTTP GraphQL/OpenAPI endpoint evaluated by schema scanners (not the NyxStrike route string).",
        "endpoints": "Relative route fragments `api_fuzzer` appends to `base_url`.",
        "schema_url": "Remote OpenAPI/Swagger/GraphQL schema URL downloaded before static analysis.",
        "schema_type": 'Parser hint such as `"openapi"`, `"swagger"`, or `"graphql"`.',
        "graphql_url": "GraphQL HTTP endpoint for dedicated GraphQL abuse checks.",
        "swagger_url": "Alternate OpenAPI discovery URL treated like `schema_url` by some connectors.",
        "jwt_token": "Raw JWT/JWS blob for decode, key confusion, or RS256→HS256 testing—handle as live secret.",
        "username": "Username for SMB/LDAP/WinRM clients and login brute modules.",
        "password": "Cleartext password for authenticated scans—rotate if leaked into logs.",
        "hash": "Verifier string for Evil-WinRM / NetExec pass-the-hash transports.",
        "hashes": "Impacket `-hashes LMHASH:NTHASH` material or equivalent for Kerberos/NTLM hops.",
        "aes_key": "Hex AES256 key for Kerberos `-aesKey` flows when passwords are unavailable.",
        "authtype": "LDAP bind mode (`NTLM`, `SIMPLE`, …) for ldapdomaindump.",
        "auth": "Compact credential or Authorization header string for Schemathesis/HTTP harnesses.",
        "auth_mode": "EAPHammer soft-AP authentication profile (OPEN, WPA2-PSK, enterprise).",
        "passphrase": "WPA PSK or Steghide passphrase for crypto operations.",
        "wep_key": "ASCII/hex WEP key for airdecap-ng decryption.",
        "share": "SMB share (`C$`, `ADMIN$`) for remote execution transports.",
        "shell_type": "Remote shell interpreter (`cmd`, `powershell`) some Impacket scripts honour.",
        "command": "Escaped command string for psexec/wmiexec/smbexec-style runners.",
        "commands": "Macro batch (`rpcclient` or `r2 -c`) replayed verbatim.",
        "script": "Impacket script basename (`GetNPUsers.py`, `secretsdump.py`).",
        "module": "Metasploit module path, Patator dialect, or NetExec plugin name.",
        "protocol": "NetExec transport (`smb`, `winrm`, `ldap`, `mssql`, …).",
        "options": "JSON map of Metasploit `set` assignments for scripted console use.",
        "extra_options": "Leading dash-options for Impacket scripts lacking structured fields.",
        "extra_args": "Trailing CLI tokens after mapped arguments for niche switches.",
        "dc_ip": "Domain controller IPv4 when DNS is untrusted or split-horizon breaks auth.",
        "wordlist": "Agent-resident newline wordlist for content/DNS/password tooling.",
        "capture_files": "`.pcap` paths with handshake material for aircrack-ng.",
        "capture_file": "Single capture for airdecap-ng decrypt passes.",
        "hash_file": "Line-delimited hashes for John/hashcat/ophcrack.",
        "password_file": "Dictionary file for Hydra/Medusa/Patator.",
        "username_file": "Username list for credential spraying modules.",
        "file_path": "Readable path for xxd/exiftool style utilities.",
        "file": "Binary/firmware specimen for binwalk/strings/checksec.",
        "binary": "Executable for radare2/ghidra/objdump/ropper workflows.",
        "libc_path": "`libc.so.6` path examined by one_gadget.",
        "image_path": "Forensic disk image for Autopsy/sleuthkit ingestion.",
        "input_file": "Evidence blob for foremost/scalpel/testdisk carvers.",
        "memory_file": "RAM dump consumed by volatility `plugin` jobs.",
        "cover_file": "Carrier file for Steghide embed/extract.",
        "embed_file": "Secret payload Steghide hides inside `cover_file`.",
        "output_file": "Explicit output path for logs/PCAPNG/JSON when CLIs support `-o`.",
        "output_dir": "Directory root for AutoRecon, foremost, Scout exports.",
        "output_prefix": "`airodump-ng` `--write` basename for rolling captures.",
        "output_urls": "Persist URL-only lines from waymore-style archive mining." + _bn(),
        "output_responses": "Persist raw HTTP bodies from waymore-style mining." + _bn(),
        "report_dir": "Schemathesis/Scout HTML/SARIF/JSON bundle root.",
        "tables_dir": "Ophcrack rainbow-table base directory.",
        "tables": "Named rainbow tables passed to ophcrack.",
        "case_name": "Autopsy logical case separating evidence SQLite stores.",
        "project_name": "Ghidra project directory for headless reversing jobs.",
        "script_file": "External automation script for Ghidra/GDB post-processing.",
        "script_content": "Inline pwntools/angr code executed before harness launch.",
        "iac_dir": "Terraform/Kubernetes manifest tree for Terrascan.",
        "directory": "Repository root for Checkov or broad filesystem Trivy scans.",
        "config_dir": "kube-bench JSON directory or auxiliary DNS config roots.",
        "config_file": "Alternate YAML for Falco, Clair, or service-specific configs.",
        "config": "cloudmapper account metadata or secondary service configuration path.",
        "rules_file": "Supplemental Falco rule pack path.",
        "ports": "Port list (`22,443`, `1-65535`) for Masscan/Nmap templates.",
        "port": "Single TCP port (for example ZAP’s local proxy) distinct from multi-port scans.",
        "scan_type": "Connector-specific profile: Nmap flags, Trivy scan class, Burp macro, or ZAP policy name.",
        "timing": "Nmap `-T0`…`-T5` template for advanced wrappers.",
        "nse_scripts": "Comma-separated NSE script list (`default,safe,vuln`).",
        "rate": "Masscan `--rate` packets-per-second ceiling—keep low outside owned networks.",
        "threads": "Concurrent workers for ffuf/arjun/sublist3r/feroxbuster HTTP jobs.",
        "workers": "Schemathesis Hypothesis worker count.",
        "timeout": "Seconds for socket/DNS/CLI overall timeouts.",
        "request_timeout": "Per-request HTTP timeout for Schemathesis.",
        "delay": "Millis or seconds between probes to reduce WAF trips (Arjun, fuzzers).",
        "duration": "Runtime cap for Responder poison loops or Falco capture windows.",
        "heartbeat": "AutoRecon status interval between internal tool stages.",
        "analysis_timeout": "Maximum Ghidra headless analysis seconds before abort.",
        "poll_interval": "Spiderfoot/long-job polling cadence when exposed.",
        "max_tools": "Smart-scan parallel tool budget.",
        "max_pages": "Burp-style spider page cap.",
        "max_depth": "Recursive crawl depth for packaged web spiders.",
        "max_examples": "Schemathesis generated-example cap per operation.",
        "max_failures": "Fail-fast threshold for flaky API fuzz campaigns.",
        "depth": "hakrawler/paramspider/gospider crawl depth.",
        "query_depth": "GraphQL nested query depth limit for scanners.",
        "level": "Commix injection depth, ophcrack gadget level, or similar integer tier.",
        "count": "`aireplay-ng` packet burst counter.",
        "retries": "Resolver retries for ShuffleDNS brute mode.",
        "resolve_count": "MassDNS simultaneous resolution concurrency (`-r`).",
        "socket_count": "Parallel MassDNS socket fan-out.",
        "interval": "Millis between MassDNS resolver batches.",
        "hashmap_size": "MassDNS internal hash buckets for gigantic wordlists.",
        "wildcard_threads": "shuffleDNS wildcard-detection parallelism.",
        "record_type": "DNS RR (`A`, `AAAA`, `TXT`) forwarded to stubs.",
        "record_types": "dig driver issues these RR types sequentially against `target`.",
        "burst_rate": "Wi‑Fi injection throttle—reduce outside shielded enclosures.",
        "certificate": "TLS certificate path some rogue-AP tooling uses for captive portals.",
        "bindto": "Local IPv4 MassDNS binds to for egress control.",
        "rcvbuf": "Kernel receive-buffer hint for MassDNS sockets.",
        "sndbuf": "Kernel send-buffer hint for MassDNS sockets.",
        "drop_user": "Unprivileged POSIX user MassDNS drops to after binding.",
        "drop_group": "Supplemental group drop for hardened MassDNS runs.",
        "error_log": "MassDNS stderr/log redirection target.",
        "filter": "MassDNS output-filter DSL restricting printed answers.",
        "ignore": "Substring denylist skipping brittle resolver targets.",
        "log_prefix": "Prefix applied to chunked log artefacts on long engagements.",
        "outfile": "Explicit MassDNS output file path.",
        "rand_src_ipv6": "Textual IPv6 source selection hint for MassDNS.",
        "random_delay": "gospider random delay between worker requests.",
        "additional_args": "Shell tokens appended after mapped CLI arguments.",
        "api_key": "Privileged bearer (ZAP API, SaaS connectors)—never ticket plain-text.",
        "interface": "Network interface (`wlan0mon`, `eth0`) for Wi‑Fi or Responder jobs.",
        "channel": "802.11 channel for captures or rogue AP broadcasts.",
        "essid": "SSID string for handshake correlation or rogue APs.",
        "bssid": "AP MAC filters for airodump/aireplay workflows.",
        "client_mac": "Station MAC for directed deauthentication bursts.",
        "action": "`airmon-ng` verb (`start`/`stop`) or CloudMapper subcommand name.",
        "attack_mode": "`aireplay-ng` attack name **or** hashcat `-a` attack id—meaning depends on catalogue entry context.",
        "attack_type": "MDK4/EAPHammer attack choreography identifier.",
        "wpa_mode": "Soft-AP cipher selection (`wpa2`, `wpa3`, …).",
        "caplet": "Bettercap `.cap` macro loaded after interface setup.",
        "mode": "High-level tool mode (Amass `enum`, gobuster `dir`, shuffleDNS profile, etc.).",
        "list": "ShuffleDNS bruteforce wordlist path.",
        "resolver": "Resolver `ip:port` for shuffleDNS active jobs.",
        "trusted_resolver": "Ground-truth resolver for shuffleDNS wildcard logic.",
        "massdns": "MassDNS binary path or helper directory for shuffleDNS glue.",
        "massdns_cmd": "Custom MassDNS launcher prefix when images differ.",
        "raw_input": "Domain corpus without normalisation for advanced DNS utilities.",
        "input": "Generic text blob for waymore/hurl data transforms.",
        "input_data": "Line block deduped by anew-style utilities.",
        "data": "sqlmap POST body, Commix injection context, or hashpump cleartext segment.",
        "body": "Raw HTTP body for x8-style hidden parameter fuzzing.",
        "headers": "HTTP headers as JSON map or newline text for replay utilities.",
        "cookies": "Cookie jar string for manual HTTP replays.",
        "cookie": "Session cookie string for authenticated gospider crawls.",
        "user_agent": "Custom User-Agent for spiders and REST fuzzers.",
        "proxy": "HTTP/S proxy URL for gospider or other HTTP utilities.",
        "burp": "Burp collaborator/proxy integration hint for auxiliary crawlers.",
        "blacklist": "Regex/glob denylist trimming spider scope.",
        "whitelist": "uro allow-regex keeping only approved URL patterns.",
        "replacement": "qsreplace token replacing query values (often `FUZZ`).",
        "payload": "msfvenom payload specifier (`windows/x64/meterpreter/reverse_tcp`).",
        "method": "HTTP verb (`GET`, `POST`, …) or tool-specific dispatcher (ffuf mode selection, HTTP-framework action cues, Arjun transport).",
        "format": "msfvenom output container (`elf`, `exe`, `raw`, `python`).",
        "lhost": "Callback host embedded in generated payloads.",
        "lport": "Callback port embedded in generated payloads.",
        "hash_type": "Hashcat mode id matching `hash_file` format (`22000`, `1000`, …).",
        "mask": "Hashcat mask syntax (`?d?d?d?d?d?d`).",
        "format_type": "John the Ripper format string (`raw-md5`, `wpapsk`, …).",
        "symbols": "Symbol offset blob identifying libc for libc-database lookups.",
        "libc_id": "libc-database download id after a match is found.",
        "cve_id": "CVE identifier for vulnx-style intel APIs.",
        "search": "Keyword search for vulnx when CVE id unknown.",
        "auth_key": "API key/bearer for premium vulnerability intel feeds.",
        "plugin": "Volatility module (`windows.pslist`, `linux_bash`, …).",
        "profile": "Volatility KDBG profile **or** named cloud CLI profile for Prowler—check tool context.",
        "analysis_type": "angr strategy (`symbolic`, `CFGFast`, …).",
        "find_address": "Hex goal for symbolic exploration.",
        "avoid_addresses": "Hex addresses excluded from symbolic paths.",
        "gadget_type": "Ropper category (`rop`, `jop`, `sys`).",
        "quality": "Ropper minimum gadget quality rank.",
        "search_string": "Mnemonic substring filter for gadget dumps.",
        "arch": "ISA hint (`x86`, `amd64`, `aarch64`) for gadget tools.",
        "libc": "Optional libc.so path for pwninit bundling.",
        "ld": "Dynamic linker path accompanying pwninit bundles.",
        "template_type": "Exploit scaffold format (`python`, `c`).",
        "exploit_type": "pwntools harness mode (`local` vs `remote`).",
        "objective": "Planner hint for smart-scan/attack-chain heuristics (`comprehensive`, `stealth`).",
        "template": "Nuclei template id glob/path when exposed by the route.",
        "tags": "exiftool tag projection or scanner tag filters.",
        "severity": "Minimum issue class for terrascan/trivy style reporting.",
        "provider": "Cloud vendor (`aws`, `azure`, `gcp`, `oci`).",
        "region": "Cloud region focus for audit connectors.",
        "checks": "CSV benchmark control ids (docker-bench), Prowler check ids, **or** Schemathesis check names—depends on route.",
        "services": "Service allowlist for Scout Suite / cloud modules.",
        "exceptions": "Scout JSON describing suppressed false positives.",
        "image": "OCI image ref (`repo:tag@sha256:…`) for Clair/Trivy.",
        "output_format": "Structured report format (`json`, `xml`, `sarif`, `html`).",
        "parameters": "BBot JSON/YAML selecting modules, safe flags, and seeds.",
        "modules": "Recon-ng module chain, Pacu module list, or related automation selector.",
        "engine": "Sublist3r search-engine string.",
        "site": "Single gospider seed URL.",
        "sites": "Multiple gospider seeds.",
        "concurrent": "gospider concurrent fetch budget per depth tier.",
        "phases": "Schemathesis comma-separated phases (`examples`, `coverage`, …).",
        "rate_limit": "Global HTTP RPS throttle for schema fuzzing.",
        "report_formats": "Schemathesis export format list (`html,json,junit`).",
        "include_operation_id": "Restrict fuzzing to these OpenAPI operationIds." + _bn(),
        "exclude_operation_id": "Skip risky OpenAPI operationIds." + _bn(),
        "transforms": "Maltego transform identifiers or descriptors.",
        "account": "CloudMapper/Prowler pseudo-account alias for mapping AWS tenancy graphs.",
        "server": "Interactsh or collaborator base URL polled for DNS/HTTP blind-callback payloads.",
        "token": "Interactsh session token tying out-of-band events to your run.",
        "n": "`interactsh` poll/request budget controlling how many callback checks occur before stopping.",
        "negotiate": "EAPHammer/downgrade knobs affecting WPA-enterprise negotiation behaviours.",
    }
    if kl in SPECIFIC and SPECIFIC[kl]:
        return SPECIFIC[kl]

    if kl in {"append_data"}:
        return "Suffix bytes appended inside hashpump length-extension forgeries."

    # Remaining booleans inferred
    GENERIC_BOOL = {
        "aggressive",
        "all_sources",
        "analyze",
        "disable_update_check",
        "follow_redirects",
        "forms",
        "headless",
        "https",
        "include_other_source",
        "include_subs",
        "introspection",
        "json",
        "kerberos",
        "mutations",
        "no_color",
        "no_pass",
        "no_redirect",
        "only_subdomains",
        "os_detection",
        "other_source",
        "probe",
        "robots",
        "sitemap",
        "stable",
        "status_code",
        "stealth",
        "strict_wildcard",
        "suppress",
        "tech_detect",
        "title",
        "update",
        "use_recovery",
        "verbose",
        "version_detection",
        "version",
        "wayback",
        "wpad",
    }

    pattern: list[tuple[callable[..., bool], str]] = [
        (lambda x=kl: x.endswith("_file") or x.endswith("_path"), f"Agent filesystem path for `{k}` consumed by the connector."),
        (lambda x=kl: x.endswith("_dir"), f"Directory on the agent used for `{k}` outputs."),
        (lambda x=kl: "wordlist" in x, "Newline wordlist path on the agent for brute/DNS/content tooling."),
        (lambda x=kl: x in {"output", "outfile"}, "Primary output sink some CLIs require (`-o`, `--output`)."),
        (lambda x=kl: "cookie" in x, "Cookie header contents for authenticated HTTP replays."),
        (lambda x=kl: x.endswith("_url"), "HTTP/S URL fetched or attacked—must include scheme."),
        (lambda x=kl: "port" in x, f"Port-related control for `{k}`; exact meaning follows the catalogue connector."),
        (lambda x=kl: x in GENERIC_BOOL, f"Boolean `{k}` mirroring upstream CLI semantics." + _bn()),
    ]
    for pred, text in pattern:
        if pred():
            return text

    return (
        f"The workspace forwards `{k}` in the Vrika POST body unchanged after stripping empty optional fields. "
        f"The NyxStrike connector binds it to the integration listed for your catalogue slug. "
        f"If executions reject the value, open the bastion-side wrapper scripts to confirm quoting, path expectations, "
        f"type coercion, or privilege requirements before escalating."
    )


def main() -> None:
    repo = Path(__file__).resolve().parents[2]
    keys = _collect_keys()
    doc = {k: {"help": _help(k)} for k in keys}
    out = repo / "vrika-agent" / "server_api" / "tools_catalog" / "param_key_help.json"
    out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    missing = [k for k in keys if not doc[k]["help"].strip()]
    assert not missing, missing
    print(f"Wrote {out} ({len(doc)} keys)")


if __name__ == "__main__":
    main()
