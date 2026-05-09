"""Structured narrative supplements and cluster-aware usage text for catalog doc generation."""

from __future__ import annotations

# (typical_outputs, positioning_vs_alternatives, scope_limits) — appended after curated lead paragraphs.
_CATEGORY_SUPPL: dict[str, tuple[str, str, str]] = {
    "ai_assist": (
        "Typical NyxStrike output combines the model transcript with summaries of artefacts already stored for the cited session.",
        "Use this connector when repeating full scans across the workspace would duplicate load; defer to planners only when deterministic "
        "tooling has already exercised the corpus.",
        "LLM backends may persist prompts or outputs under provider policy—strip secrets and scope identifiers before analysing.",
    ),
    "vulnerability_intelligence": (
        "Expect structured vulnerability records pulled from aggregated feeds: identifiers, summaries, remediation pointers, "
        "and referencing links rather than exploitation proof.",
        "Reach for vulnx-class routes when correlating disclosures during triage instead of brute-forcing local mirrors with searchsploit "
        "or hitting vendor APIs manually.",
        "Intel licensing varies by source; redistribution outside the tenancy may violate vendor terms.",
    ),
    "osint": (
        "Results are textual lists, JSON artefacts, archive URLs, or passive reconnaissance breadcrumbs suitable for ingestion into trackers.",
        "OSINT tooling should precede intrusive scanning wherever policy demands minimal touch; escalate to DNS brute or crawler stages "
        "only after validating scope wording.",
        "Passive APIs throttle aggressively and may log lookups under shared keys—credential handling matters.",
    ),
    "web_recon": (
        "Output usually enumerates reachable paths, crawler graphs, fingerprints, robots hints, deduplicated URLs, or header snapshots.",
        "Combine directory bruteforce, spidering, and header probes sequentially: surface mapping before attempting injection payloads.",
        "Misconfigured crawlers crawl out of scope rapidly—align seed URLs, blacklist regexes, and depth caps with authorised programs.",
    ),
    "essential": (
        "Core utilities return concise stdout suited for piping into scanners or parsers (DNS answers, registrar text, binaries, transports).",
        "Reserve essential connectors for repeatable plumbing when higher-level arsenals obscure parameters you must control explicitly.",
        "Even ancillary utilities honour the same egress rules—do not widen targets implicitly via glob inputs.",
    ),
    "network_recon": (
        "Expect port listings, traceroute-like hints, service banners, NIC inventories, handshake captures, or ARP inventories depending on tooling.",
        "Fast SYN scanners suit huge ranges; balanced scanners add scripts and versioning; SMB-oriented tools deepen Windows visibility—choose "
        "based on scope scale and covertness mandates.",
        "High packet rates overwhelm small networks—rate-limit, subdivide subnets, and obtain written approval before touching neighbouring tenants.",
    ),
    "fingerprint": (
        "Outputs highlight technology stacks inferred from artefacts you already harvested from HTML, TLS metadata, HTTP responses, "
        "and similar signals.",
        "Use fingerprints to prioritise vuln hunts that actually apply to surfaced components instead of blindly launching every template pack.",
        "Inference is probabilistic—verify findings manually before escalating to intrusive checks.",
    ),
    "wifi_pentest": (
        "802.11 harnesses emit captures, WPA hash material, rogue AP scaffolding, injector acknowledgements, and audit logs keyed to channels/BSSIDs.",
        "Laboratory rigs should dedicate monitor-mode interfaces plus isolated spectrum; tethered enterprise APs rarely tolerate injection homework.",
        "Jamming neighbours or intercepting unauthorised traffic violates law—operate strictly inside sanctioned RF enclosures and licensed bands.",
    ),
    "web_vuln": (
        "Structured runs usually report vulnerable parameters, collaborator callbacks, payloads attempted, timings, tamper artefacts, "
        "and shell evidence when enabled.",
        "Automation accelerates repeatable bug classes yet still requires manual corroboration; pair with benign accounts and isolated databases.",
        "Exploit payloads can corrupt data stores or escalate privileges—replay only artefacts provisioned explicitly for drills.",
    ),
    "web_scan": (
        "Engines focus on CGI-era misconfigurations, header hygiene, obsolete modules, dangerous methods, or template findings—expect verbose text logs.",
        "Use broad scanners early to spot low-hanging misconfigurations, then escalate to focussed nuclei/ffuf workloads for targeted regressions.",
        "Large requests may trip WAF quotas—coordinate throttling factors with SOC playbooks.",
    ),
    "brute_force": (
        "Output enumerates guessed credentials, cracked hashes, cracked handshakes, or rule-engine statistics keyed to service modules.",
        "Credential attacks belong after softer enumeration proves plausible usernames/services; brute force last to avoid cascading lockouts.",
        "Always enforce attempt ceilings, alerting hooks, and service-owner approval—plaintext secrets land in bastion transcripts.",
    ),
    "binary": (
        "Debuggers/disassemblers/gadget hunters produce listings, scripted traces, annotated graphs, emulation logs, or CTF scaffolding.",
        "Static analysis excels on offline artefacts; symbolic tooling demands compute and may path-explode on large binaries.",
        "Malware-grade samples may trigger host controls—sandbox accordingly and sanitise artefacts before sharing externally.",
    ),
    "cloud": (
        "Cloud posture connectors emit JSON/HTML/SARIF findings enumerating IAM sprawl, open buckets, CIS deviations, stale keys, "
        "and attack-path narratives.",
        "Cloud scans require least-privilege API roles scoped to enumerated accounts—not root keys embedded in plaintext JSON long term.",
        "Provider APIs log every call; minimise repeated broad scans and purge credentials promptly after tabletop windows.",
    ),
    "api": (
        "API tooling highlights schema quirks, undocumented parameters, malformed JWT behaviours, fuzz deltas, "
        "and property-test regressions referencing OpenAPI/GraphQL artefacts.",
        "Schema-first testers complement browser-only assessments by exercising machine contracts that never render in GUIs.",
        "Generated traffic can cascade into billing or email workflows—narrow operationIds and verbs before unattended fuzzing.",
    ),
    "exploitation": (
        "Metasploit/payload harnesses expose sessions, staged shellcode artefacts, staged listeners, meterpreter transcripts, "
        "and failure diagnostics.",
        "Exploitation tooling is for labs with containment; maintain VM snapshots because modules may patch or crash unstable services.",
        "Payload generation can trip AV egress controls—isolate build hosts and watermark binaries for traceability.",
    ),
    "lateral_movement": (
        "Impacket-style transports return command stdout, SID dumps, ticketing warnings, DPAPI extracts, "
        "or benign RPC listings depending on wrappers.",
        "Remote execution primitives differ in OPSEC footprints—prioritise WinRM auditing accounts over noisy SMB relays when "
        "defenders mandate stealth.",
        "Kerberos materially depends on reachable DCs accurate clocks and careful hash handling.",
    ),
    "active_directory": (
        "AD helpers export user lists, trusts, constrained delegations, policy summaries, responder captures, SMB maps, LDAP dumps.",
        "Use dedicated assessment domain accounts wherever possible—these emits land in Defender and SIEM timelines.",
        "Credential material in transit may enable domain-wide compromise—treat transcripts as collateral damage.",
    ),
    "intelligence": (
        "Intelligence routers combine analysis, chaining, profiling, orchestration manifests, AI-selected toolplans, "
        "and explanatory narratives about why certain jobs fire.",
        "Smart planners trade determinism for speed—validate proposed fan-outs before unattended execution on sensitive ranges.",
        "Automated chains still require human scope checks before touching regulated data classifications.",
    ),
    "forensics": (
        "Forensic tooling streams carved files, timelines, entropy maps, PCAP decodes, volatility tables, SQLite extractions.",
        "Forensic artefacts may contain HIPAA/PII regulated content—encrypt exports immediately.",
        "Resource-heavy jobs need disk-bound IO quotas; carve only targeted ranges when multi-terabyte images are mounted.",
    ),
    "database": (
        "Database probes show schema excerpts, benign SQL probe results, latency statistics, credential failures.",
        "Use least-privilege database accounts with read-mostly grants unless destructive testing is chartered.",
        "SQL strings echo to DB audit logs alongside NyxStrike—avoid production accounts without rollover plans.",
    ),
    "monitoring": (
        "Runtime monitors bubble syscall anomalies, CIS benchmark deltas, ephemeral capture excerpts.",
        "Falco/kube-bench class tooling helps validate purple-team detections—not as offensive weapons.",
        "Kernel-level monitors jitter performance—coordinate maintenance windows.",
    ),
    "data_processing": (
        "Pipeline gadgets emit deduped URL streams, mutated query dictionaries, novelty markers consumed by fuzzers downstream.",
        "Pair urltooling early in pipelines to cut noise feeding ffuf nuclei pipelines.",
        "Massive stdin lines stress memory filters—chunk inputs when chaining shell pipes via agents.",
    ),
}

UNCATEGORIZED_SUPPL = (
    "Outputs follow the bundled wrapper format for this catalogue id—structured runner metadata plus streamed stdout/err.",
    "Compare alternatives by reading neighbouring catalogue entries covering the same subsystem; escalate cautiously.",
    "Respect organisational rules about data retention and logging for every outbound request.",
)


_TOOL_SUPPL: dict[str, tuple[str, str, str]] = {
    "nmap": (
        "Nmap returns host discovery summaries, TCP/UDP state tables (`open|filtered|closed`), scripted findings, traceroute breadcrumbs, "
        "optional OS guesses, and NSE artefacts depending on selections.",
        "Choose Nmap when you need balanced coverage with scripting fingerprints; defer to Masscan or Rustscan for Internet-scale sweeps, "
        "then deepen hot hosts with targeted Nmap passes.",
        "Privileged SYN scans (`-sS`) require raw sockets; UDP passes are noisy and slow.",
    ),
    "nmap_advanced": (
        "Advanced routes expose scripted timing templates granular NSE lists OS detection toggles stealth switches and sanctioned passthrough "
        "segments while remaining JSON-first.",
        "Identical differentiation as base Nmap but with fuller control surfaces for mature operators automating regressions.",
        "Malformed `additional_args` easily break quoting—trial on lab hosts.",
    ),
    "masscan": (
        "Masscan prints asynchronous handshake outcomes at extreme speeds using its isolated TCP stack summaries.",
        "Use Masscan before Nmap when you must enumerate broad CIDRs quickly—but always constrain rates and reconcile with ICMP discovery gaps.",
        "Asynchronous pacing can saturate uplinks causing collateral packet loss alarms.",
    ),
    "rustscan": (
        "Rustscan bursts port lists then optionally forwards live hosts toward Nmap fingerprints.",
        "Select Rustscan for developer-speed triage loops; pivot to scripted Nmap batches for nuanced service telemetry.",
        "Batch sizing and timeouts interact with kernel buffers—mis-tuning loses responses on busy segments.",
    ),
    "massdns": (
        "MassDNS streams enormous resolver datasets with hashing-friendly outputs plus optional flushing controls.",
        "Pair MassDNS upstream of shuffleDNS or internal analytics when brute lists exceed millions of queries.",
        "Resolver abuse triggers ISP abuse desks—whitelist resolvers throttle concurrency and purge sensitive labels.",
    ),
    "shuffledns": (
        "shuffleDNS normalises brute inputs runs wildcard detection leverages trusted resolver baselines emits JSON summaries.",
        "Use shuffleDNS orchestration whenever ProjectDiscovery-compatible DNS workflows demand MassDNS backends with PD ergonomics.",
        "Misconfigured wildcard logic yields false negatives—supply trusted resolver pairs from scope owners.",
    ),
    "enum4linux": (
        "Legacy enum4linux lumps rpcclient net users smbclient heuristics into Perl-era tables.",
        "Prefer enum4linux-ng unless you deliberately reproduce classical script output for regressions.",
        "Null sessions rarely succeed on modern domains—supply credentialed context when mandated.",
    ),
    "enum4linux-ng": (
        "enum4linux-ng emits JSON-friendly summaries Rid cycles Kerberos aware toggles granular share maps.",
        "Default to NG for greener assessments; fallback to legacy enum4linux only when parsers expect historical formats.",
        "Aggressive Rid cycling trips detections throttle consciously.",
    ),
    "sqlmap": (
        "sqlmap reports injection classes payloads tamper combos extracted table fragments plus timing histograms.",
        "Reserve sqlmap once manual triage validates candidate parameters tamper combos belong to chartered DBMS families.",
        "Data exfil payloads may violate privacy charters—clamp `--dump` equivalents via policy.",
    ),
    "hydra": (
        "Hydra prints cracked credentials per-module attempt counts and handshake diagnostics.",
        "Hydra excels at multiprotocol brute forcing versus Medusa emphasis or Patator extensibility.",
        "Parallel threads may lock accounts maintain delay flags.",
    ),
    "patator": (
        "Patator emits Pythonic verbosity with modular transports covering SMB HTTP databases.",
        "Reach for Patator when hydra-medusa lacks required modules—not for stealth.",
        "Verbose modules leak secrets into logs.",
    ),
    "medusa": (
        "Medusa emphasises stable parallel transport modules with predictable output tables.",
        "Choose Medusa for simpler parallel modules hydra lacks Patator retains scriptability.",
        "Tune `threads` to respect lockout policies.",
    ),
    "nuclei": (
        "Nuclei aggregates YAML severity tagged findings clustered by host template metadata optional collaborator hooks.",
        "Nuclei templates replace bespoke curl scripts iterate faster than Nikto CGI sweeps albeit with template maintenance overhead.",
        "Aggressive templates may contain destructive payloads read template metadata before unattended runs.",
    ),
    "nikto": (
        "Nikto logs verbose CGI misconfig risky headers obsolete modules Tomcat fingerprints.",
        "Nikto excels at shotgun webserver regression sweeps complementary to nuclei's template specificity.",
        "Huge output buries actionable items triage diligently.",
    ),
    "dalfox": (
        "DalFox emits reflected stored blind XSS correlations optional collaborator callbacks mined parameters.",
        "Pair DalFox with crawler-derived parameters before generic XSS sprays.",
        "Stored XSS payloads can harm real users sanitise QA tenants.",
    ),
    "ffuf": (
        "ffuf outputs tabular fuzz results keyed by fuzz slots across directions, statuses, sizes, redirects, "
        "and complementary metadata when matchers are tuned.",
        "ffuf excels at simultaneous verb header route body fuzz nucleation versus gobuster simplicity.",
        "High concurrency trips WAFs align threads delay.",
    ),
    "feroxbuster": (
        "Feroxbuster streams recursive crawler aware responses depth aware heuristics.",
        "Prefer feroxbuster over gobuster ffuf combos when recursion depth concurrency must stay unified.",
        "Recursive mis-scoping enumerates unintended vhosts blacklist explicitly.",
    ),
    "wireshark": (
        "GUI Wireshark transcripts decode filters export packages—normally lab only when headless watchers insufficient.",
        "Graphical decodes help humans correlate streams automated tshark better for pipelines.",
        " PCAPs expose credentials never share raw captures casually.",
    ),
    "tshark": (
        "tshark emits text decodes exporters stats suitable for scripted analysis.",
        "Use tshark in CI reproducible hunts reserve Wireshark GUIs for deep dives.",
        "Display filters differ from capture filters misunderstandings omit evidence.",
    ),
    "bettercap": (
        "Bettercap merges Wi-Fi BLE Ethernet MITM scripting caplets telemetry.",
        "Bettercap contrasts with legacy aircrack toolchain by offering unified scripting albeit heavier dependencies.",
        "MITM tooling is adversarial emulate only sanctioned labs.",
    ),
    "responder": (
        "Responder emits captured hashes poisoning logs responder modules duration bounded captures.",
        "Responder complements Impacket dumping after LLMNR/NBT-NS poisoning succeeds.",
        "Broadcast poisoning harms VOIP fleets isolate VLANs.",
    ),
    "msfconsole": (
        "msfconsole transcripts include module consoles jobs sessions resource script errors.",
        "Metasploit remains reference for staged exploits coordinating listeners though noisier than custom tooling.",
        "Payload handlers open listener ports tighten firewall narratives.",
    ),
    "msfvenom": (
        "msfvenom prints encoder summaries payload bytes optional templates.",
        "msfvenom centralises staged payload recipes versus compiling shellcode manually.",
        "Artifacts must stay inside malware analysis pipelines.",
    ),
    "interactsh": (
        "Interactsh correlates collaborator DNS HTTP interactions with seeded tokens tying blind sinks.",
        "Use after mapping injection points needing out-of-band confirmation.",
        "Self-hosted relays require infra approval.",
    ),
    "jwt-analyzer": (
        "JWT tooling emits decoded segments confusion attack verdicts brute force hints optional replay artefacts.",
        "Differentiates from graphql scanners by specialising JOSE cryptographic misuse.",
        "Weak secret dictionaries belong to chartered pentests.",
    ),
    "http-framework": (
        "HTTP framework connector mirrors curl ergonomics verbs bodies cookies replay chains.",
        "Useful for bespoke asserts before scripting python requests pipelines.",
        "Manual verbs can mutate production data beware non-idempotent POSTs.",
    ),
    "schemathesis": (
        "Schemathesis merges Hypothesis-backed fuzzing with phased OpenAPI/GraphQL coverage and exportable artefacts (HTML/JUnit/SARIF).",
        "Property-based runs outperform ad hoc curl suites for contract regressions though they consume more runtime and flaky services need tuning.",
        "Watch check toggles (`checks`) carefully—automated validations can amplify noise on brittle endpoints.",
    ),
}


def supplement_for(tool: str, category: str) -> tuple[str, str, str]:
    if tool in _TOOL_SUPPL:
        return _TOOL_SUPPL[tool]
    return _CATEGORY_SUPPL.get(category) or UNCATEGORIZED_SUPPL


def cluster_for(tool: str) -> str:
    match tool:
        case (
            "analyze-target"
            | "create-attack-chain"
            | "preview-attack-chain"
            | "smart-scan"
            | "technology-detection"
        ):
            return "cipherstrike_intelligence"
        case "ai_analyze_session":
            return "ai_session_summaries"
        case "vulnx":
            return "vulnerability_intel_queries"
        case "waymore":
            return "historic_url_archive"
        case "nmap" | "nmap_advanced":
            return "nmap_scanner"
        case "masscan":
            return "masscan_syn_sweep"
        case "rustscan":
            return "rustscan_adaptive"
        case "enum4linux":
            return "legacy_smb_enum"
        case "enum4linux-ng":
            return "modern_smb_enum"
        case "smbmap":
            return "smb_share_mapper"
        case "arp-scan":
            return "l2_arp_inventory"
        case "gobuster" | "dirb":
            return "classic_dir_bruteforce"
        case "ffuf" | "wfuzz":
            return "multi_slot_http_fuzz"
        case "feroxbuster":
            return "recursive_content_discovery"
        case "katana" | "gospider":
            return "javascript_aware_spider"
        case "httpx":
            return "live_host_probe"
        case "hurl":
            return "encoder_decoder_util"
        case "testssl":
            return "transport_layer_audit"
        case "dirsearch":
            return "advanced_dir_discovery"
        case "wafw00f":
            return "waf_fingerprint"
        case "wpscan" | "joomscan":
            return "cms_scanner_suite"
        case "interactsh":
            return "oob_callback_correlation"
        case "nuclei":
            return "yaml_template_runner"
        case "nikto":
            return "cgi_server_audit"
        case "sqlmap":
            return "automated_sqli"
        case "dalfox" | "xsser":
            return "focused_xss"
        case "dotdotpwn":
            return "traversal_fuzzer"
        case "jaeles":
            return "signature_web_hunter"
        case "commix":
            return "command_injection_hunter"
        case "msfvenom":
            return "payload_stager_builder"
        case "hydra" | "medusa" | "patator":
            return "credential_bruteforce"
        case "hashcat":
            return "gpu_hash_recovery"
        case "john" | "hashid" | "ophcrack" | "hashcat-utils":
            return "cpu_rainbow_hash_audit"
        case "ldapdomaindump":
            return "ldap_ad_dump"
        case "impacket-scripts":
            return "generic_impacket_cli"
        case "impacket-spec":
            return "impacket_arg_introspection"
        case "impacket-ad-enum":
            return "curated_impacket_enum"
        case "impacket-remote-exec":
            return "curated_impacket_exec"
        case "parsero":
            return "robots_path_miner"
        case "whois":
            return "registration_lookup"
        case "http-headers":
            return "minimal_header_fetch"
        case "dig":
            return "bind_style_dns"
        case "amass":
            return "recursive_dns_intel"
        case "subfinder":
            return "passive_subdomain_intel"
        case "assetfinder":
            return "compact_subdomains"
        case "shuffledns":
            return "shuffle_bruteforce"
        case "massdns":
            return "resolver_stub_storm"
        case "sublist3r":
            return "engine_subdomain_hints"
        case "fierce" | "dnsenum":
            return "traditional_dns_auditor"
        case "gau" | "waybackurls":
            return "historic_url_collectors"
        case "theHarvester":
            return "multi_source_intel_crawler"
        case "nbtscan":
            return "netbios_sweeper"
        case "rpcclient":
            return "samba_rpc_macros"
        case "bettercap":
            return "bettercap_platform"
        case "hcxdumptool" | "hcxpcapngtool" | "wifite" | "mdk4" | "eaphammer" | "airbase-ng":
            return "advanced_wifi_lab"
        case "aircrack-ng" | "airdecap-ng":
            return "psk_crack_decrypt"
        case "airmon-ng" | "airodump-ng" | "aireplay-ng":
            return "classic_aircrack_lab"
        case "kismet":
            return "passive_rf_sensor"
        case "checksec" | "strings" | "xxd" | "file":
            return "binary_triage_util"
        case "binwalk" | "foremost" | "scalpel" | "bulk_extractor" | "photorec" | "testdisk":
            return "forensic_carvers"
        case "ropgadget" | "ropper" | "one-gadget" | "libc-database":
            return "rop_libc_tooling"
        case "radare2" | "objdump" | "gdb" | "angr" | "ghidra":
            return "deep_binary_analysis"
        case "pwntools" | "pwninit":
            return "exploit_scaffolding"
        case "hakrawler":
            return "golang_link_spider"
        case "autorecon":
            return "orchestrated_recon"
        case "graphql-scanner":
            return "graphql_abuse"
        case "jwt-analyzer":
            return "jwt_crypto_tests"
        case "api-schema-analyzer":
            return "schema_policy_review"
        case "arjun":
            return "param_discovery_active"
        case "paramspider":
            return "param_historic_mining"
        case "x8":
            return "hidden_param_diffing"
        case "qsreplace" | "anew" | "uro":
            return "url_pipeline_transform"
        case "volatility" | "vol":
            return "memory_forensics"
        case "steghide" | "stegsolve" | "zsteg" | "outguess":
            return "stego_lab"
        case "exiftool":
            return "metadata_mutator"
        case "hashpump":
            return "length_extension_lab"
        case "pacu" | "cloudmapper" | "prowler" | "scout-suite":
            return "cloud_posture_graph"
        case "trivy" | "clair" | "docker-bench-security" | "checkov" | "terrascan" | "kube-bench" | "falco":
            return "policy_compliance_scan"
        case "kube-hunter":
            return "kubernetes_redteam"
        case "bbot":
            return "bbot_osint_engine"
        case "nxc":
            return "netexec_multi_protocol"
        case "evil-winrm":
            return "ruby_winrm_shell"
        case "msfconsole":
            return "metasploit_console"
        case "searchsploit":
            return "exploitdb_lookup"
        case "whatweb":
            return "fingerprint_blitz"
        case "burpsuite" | "zaproxy":
            return "gui_web_scanner"
        case "http-framework":
            return "http_framework_replay"
        case "api_fuzzer":
            return "rest_surface_mapper"
        case "schemathesis":
            return "openapi_property_fuzz"
        case "sherlock":
            return "username_osint"
        case "recon-ng" | "maltego" | "spiderfoot":
            return "osint_platform"
        case "responder":
            return "llmnr_poisoning"
        case "autopsy" | "sleuthkit":
            return "disk_case_workflow"
        case "wireshark" | "tshark" | "tcpdump":
            return "packet_capture_analysis"
        case "mysql" | "sqlite3":
            return "sql_cli_probe"
        case _:
            return "generic_connector"


_SAFETY_TOOL_NOTES: dict[str, str] = {
    "masscan": "Packet floods can trigger upstream DDoS mitigations—start with small rates and expand only on owned ranges.",
    "massdns": "Resolver storms look like botnet traffic; private resolvers and hard caps are mandatory outside isolated labs.",
    "rustscan": "Rustscan’s default aggression can overwhelm firewalls—align batch sizes with network owners.",
    "sqlmap": "Automated extraction can export regulated columns—use allowlists and isolated databases.",
    "hydra": "Parallel login attempts may trip global lockouts—coordinate account policies and cooldowns.",
    "medusa": "Same lockout cautions as Hydra; prefer service-specific throttles.",
    "patator": "Verbose logging may record cracked secrets—restrict log destinations.",
    "msfconsole": "Exploit modules may destroy services; maintain VM snapshots and segregate listener hosts.",
    "msfvenom": "Generated binaries are indistinguishable from real malware—label, hash, and store securely.",
    "responder": "Broadcast poisoning affects every host on the segment—never cross into production VLANs without isolation.",
    "bettercap": "Transparent proxies intercept sensitive transactions—use dedicated hardware labs only.",
    "aireplay-ng": "Deauthentication floods disrupt legitimate users—illegal outside consented RF cages.",
    "mdk4": "Destruction testing can brick cheap APs—expect hardware failures.",
    "eaphammer": "Enterprise downgrades impact corporate Wi-Fi—only attempt with written spectrum control.",
    "commix": "Command injection success may yield remote shells—contain egress immediately.",
    "impacket-remote-exec": "Remote execution is high severity; record every command and preserve chain-of-custody.",
    "evil-winrm": "Interactive shells alter target state—use evidence-friendly logging.",
    "nxc": "CrackMapExec descendants are loud on SMB—expect EDR correlation.",
    "burpsuite": "Active scanning can modify business data—scope forms and database seeds explicitly.",
    "zaproxy": "Automated attacks may submit forms or reset sessions—run against disposable tenants.",
    "schemathesis": "Property-based fuzzing can create resources or send mail—use synthetic environments.",
    "api_fuzzer": "REST fuzzing may hit destructive verbs—blacklist admin routes first.",
    "wireshark": "PCAP files may hold credentials or PII—encrypt archives and limit distribution.",
    "tcpdump": "Promiscuous taps may capture sensitive payloads—follow lawful intercept policies.",
    "mysql": "SQL statements may modify data even when read-only intent—use replica sandboxes when possible.",
}


def safety_appendix(tool: str) -> str:
    return _SAFETY_TOOL_NOTES.get(tool, "")


_CLUSTER_USAGE: dict[str, str] = {
    "cipherstrike_intelligence": (
        "1. Confirm the written scope authorises automated intelligence or orchestration against the supplied target.\n"
        "2. Populate `target` with the exact hostname, URL, or asset identifier your engagement letter lists—no implicit wildcards.\n"
        "3. For `smart-scan`, tune `objective` and `max_tools` so the planner cannot fan out beyond your risk appetite; "
        "review the proposed fan-out in session logs before accepting unattended runs.\n"
        "4. `preview-attack-chain` avoids persistence—use it first, then run `create-attack-chain` only when stored hypotheses are required.\n"
        "5. Interpret AI output as advisory: validate every recommended action with deterministic tooling and customer policies.\n"
        "`additional_args` is rarely used on these routes; prefer structured fields."
    ),
    "ai_session_summaries": (
        "1. Collect the `session_id` from the CipherStrike session you want reviewed—no other payload is required.\n"
        "2. Ensure the session already contains the artefacts you expect the model to reason over; this route does not launch scanners.\n"
        "3. Review the returned narrative for sensitive names or credentials before sharing outside the assessment channel.\n"
        "4. If the model references missing context, re-run prerequisite tools and append their logs to the session before re-analysing."
    ),
    "vulnerability_intel_queries": (
        "1. Supply either `cve_id` for a focused pull or `search` for keyword discovery—avoid blank queries that force broad downloads.\n"
        "2. When `auth_key` is required, load the vendor-approved secret; never append raw keys to `additional_args`.\n"
        "3. Map returned metadata to internal ticketing; do not treat CVE descriptions as exploit guarantees.\n"
        "4. Archive only what license terms allow—some feeds forbid redistribution."
    ),
    "historic_url_archive": (
        "1. Provide `input` using the domain, scope seed, or archive token expected by the packaged waymore profile.\n"
        "2. Choose `mode` and output toggles (`output_urls`, `output_responses`) based on whether you need bare URLs or stored HTTP bodies.\n"
        "3. Expect large artefacts when response capture is enabled—stage disk on the agent host accordingly.\n"
        "4. Historical captures may include personal data; scrub before exporting."
    ),
    "nmap_scanner": (
        "1. Enumerate `target` exactly as approved (single host, CIDR, or file reference per connector contract).\n"
        "2. Map scan intent to `ports`, `scan_type`, `timing`, and boolean service/OS detection flags before touching `additional_args`.\n"
        "3. Advanced entries should align `nse_scripts` and stealth toggles with SOC notification requirements.\n"
        "4. Read output chronologically: host discovery, port states, then scripts; treat `filtered` as inconclusive without follow-up.\n"
        "5. Reserve `additional_args` for flags not exposed as first-class JSON fields after verifying the NyxStrike template supports them."
    ),
    "masscan_syn_sweep": (
        "1. Limit `target` to cleared ranges; Masscan’s speed makes accidental neighbour scanning common.\n"
        "2. Set `rate`, `ports`, and interface selections conservatively; document the chosen packets-per-second in run notes.\n"
        "3. Expect binary-friendly output—pipe results into Rustscan/Nmap for deeper fingerprints.\n"
        "4. Never raise rate to defeat upstream QoS; coordinate with network owners if drops appear."
    ),
    "rustscan_adaptive": (
        "1. Provide host lists or CIDRs via `target` and align `ports` with the coverage window you need.\n"
        "2. Tune batch size and timeout fields (per registry optional map) to match NIC/driver capabilities.\n"
        "3. When Rustscan hands off to Nmap, capture both outputs to preserve evidence of open services.\n"
        "4. Watch for false negatives on lossy Wi-Fi or VPN paths—retest critical hosts calmly."
    ),
    "legacy_smb_enum": (
        "1. Supply `target` for the Windows/Samba host and optional credentials if null sessions are disabled.\n"
        "2. Enable verb-style toggles for users, shares, or policy dumps as exposed by the JSON schema.\n"
        "3. Expect noisy RPC chatter—run during approved windows and capture stdout for reporting.\n"
        "4. Pair output with `enum4linux-ng` or `nxc` when modern controls block legacy behaviours."
    ),
    "modern_smb_enum": (
        "1. Provide `target`, optional creds, and Kerberos-related toggles exactly as the wrapper documents.\n"
        "2. Prefer JSON mode when available for downstream parsing; fall back to classic text when comparing with historic reports.\n"
        "3. Validate sensitive share paths manually before attempting write tests elsewhere.\n"
        "4. Use `additional_args` only for niche switches after reproducing them manually on a lab DC."
    ),
    "smb_share_mapper": (
        "1. Enter `target`, share, and credential material per engagement policy—rotate secrets afterwards.\n"
        "2. Decide whether command execution helpers are in scope; disable them when read-only mapping suffices.\n"
        "3. Capture share permission tables from stdout; they feed privilege escalation narratives.\n"
        "4. Large share trees take time—scope recursion options if the connector exposes them."
    ),
    "l2_arp_inventory": (
        "1. Select the correct `interface` on the same broadcast domain as your targets; ARP never crosses routers.\n"
        "2. Trim `target` ranges to what is authorised—ARP sweeps touch every host on the LAN.\n"
        "3. Merge results with DHCP logs to spot rogue devices.\n"
        "4. Expect duplicate entries when laptops roam; deduplicate by MAC."
    ),
    "classic_dir_bruteforce": (
        "1. Provide `url` or `target` with scheme, optional `wordlist`, and HTTP tuning knobs (`threads`, `extensions`, `status_codes`).\n"
        "2. Start with a small wordlist to validate scope, then scale—large runs resemble DDoS traffic.\n"
        "3. Compare HTTP status, response length, and redirect chains; manual confirmation kills false positives.\n"
        "4. `additional_args` should only carry flags missing from the JSON mapper."
    ),
    "multi_slot_http_fuzz": (
        "1. Define the `FUZZ`/`FFUF` keyword placement in `url`, headers, or data fields per this connector’s template.\n"
        "2. Load wordlists and configure matchers/filters to ignore static 404 pages.\n"
        "3. Keep concurrency aligned with WAF rate limits; use `delay` options when present.\n"
        "4. Log successful fuzz slots for replay in Burp or ZAP if deeper manual testing is required."
    ),
    "recursive_content_discovery": (
        "1. Seed with the highest privileged base URL allowed, then tune `depth`, `threads`, and status filters.\n"
        "2. Monitor disk usage—recursive crawlers fan out quickly on content-heavy apps.\n"
        "3. De-duplicate against `uro`/`anew` pipelines before feeding nuclei.\n"
        "4. Validate out-of-scope link filters before launching overnight jobs."
    ),
    "javascript_aware_spider": (
        "1. Provide one or more seed URLs and optional proxy, cookie, or depth controls.\n"
        "2. Enable JavaScript parsing only when headless components are permitted—more CPU, more scope risk.\n"
        "3. Capture stdout URL streams into your evidence store; they anchor later parameter mining.\n"
        "4. Use `additional_args` for crawler-specific flags absent from first-class fields."
    ),
    "live_host_probe": (
        "1. Feed newline files or lists via `target`/`url` fields as defined in the registry entry.\n"
        "2. Toggle technology detection, title extraction, and status flags to match reporting needs.\n"
        "3. Treat non-responses as dead paths—follow up with ping/TCP checks if UDP-only services matter.\n"
        "4. Batch huge inputs to keep memory predictable on the agent."
    ),
    "encoder_decoder_util": (
        "1. Provide the `input` blob plus the transform mode expected by the hurl-style wrapper.\n"
        "2. Use this tool for payload preparation—not for delivering exploits directly.\n"
        "3. Validate outputs manually when encodings chain (e.g., hex then URL).\n"
        "4. Avoid secrets in shared sessions; encoders log inputs verbatim."
    ),
    "transport_layer_audit": (
        "1. Point `target` at host:port or URL forms accepted by testssl.sh packaging.\n"
        "2. Choose probe depth flags (ciphers, headers, vulnerabilities) via structured fields before `additional_args`.\n"
        "3. Expect lengthy output—grep for `NOT ok`/`LOW` severity markers when triaging.\n"
        "4. Document mitigations per finding; some warnings are informational on legacy appliances."
    ),
    "advanced_dir_discovery": (
        "1. Supply base URL, extensions, recursion, thread, and filter options mirroring dirsearch semantics.\n"
        "2. Seed wordlists appropriate to the technology stack (API vs static site).\n"
        "3. Watch for WAF captcha responses—back off when HTTP 403 patterns repeat.\n"
        "4. Export hits to spreadsheets for manual verification."
    ),
    "waf_fingerprint": (
        "1. Provide `url` for the protected application entry point.\n"
        "2. Run before heavy fuzzing to understand blocking behaviour.\n"
        "3. Compare output signatures with vendor documentation to tune bypass research ethically.\n"
        "4. Do not use identified weaknesses against systems outside scope."
    ),
    "cms_scanner_suite": (
        "1. Include `url`, optional API tokens, and enumeration toggles for users or plugins.\n"
        "2. Expect aggressive plugins list—validate versions manually before claiming exploitability.\n"
        "3. Throttle brute-force modules; many CMS tools include login tests.\n"
        "4. Archive JSON output for regression testing after patching."
    ),
    "oob_callback_correlation": (
        "1. Configure `server`, `token`, and polling budget `n` per your Interactsh deployment.\n"
        "2. Embed the issued correlation ID into blind XSS, SSRF, or deserialization gadgets.\n"
        "3. Monitor callback timelines; absence of hits is inconclusive if egress filters block traffic.\n"
        "4. Self-host brokers when customer policy forbids third-party callbacks."
    ),
    "yaml_template_runner": (
        "1. Point `target` inputs (hosts, URLs) at approved assets and choose template directories or tags via structured fields.\n"
        "2. Start with low-severity templates, then escalate only after customer sign-off.\n"
        "3. Parse JSONL output for `critical`/`high` hits and manually confirm exploitability.\n"
        "4. Keep custom templates under version control; accidental destructive checks happen via typos."
    ),
    "cgi_server_audit": (
        "1. Supply `target` root URLs; Nikto will crawl auxiliary paths aggressively.\n"
        "2. Expect verbose positives—correlate with contemporary threat models because many checks are historical.\n"
        "3. Pair with `whatweb` or `nuclei` for modern coverage.\n"
        "4. Rate-limit when reverse proxies are sensitive to duplicate requests."
    ),
    "automated_sqli": (
        "1. Provide `url`, parameter hints, data blobs, and tamper options exactly as the wrapper maps from sqlmap.\n"
        "2. Run only against consenting databases; start with `--technique` equivalents exposed as JSON fields.\n"
        "3. Review data exfiltration settings—disable dumping unless charters allow it.\n"
        "4. Log tamper selections to reproduce findings deterministically."
    ),
    "focused_xss": (
        "1. Supply target URLs/parameters and optional crawler hooks/colaborator URLs.\n"
        "2. Start with benign payloads verifying reflection, then escalate using prepared polyglots.\n"
        "3. Capture proofs without impacting real users—use labs or seeded accounts.\n"
        "4. Integrate DalFox/XSSer output with ticketing for developer reproduction."
    ),
    "traversal_fuzzer": (
        "1. Provide protocol-specific targets (HTTP, FTP, etc.) per the packaged dotdotpwn profile.\n"
        "2. Choose module and depth options conservatively—traversal payloads may read sensitive files.\n"
        "3. Stop immediately when evidence proves impact; export logs for remediation teams.\n"
        "4. Do not aim traversal templates at unmanaged third-party estates."
    ),
    "signature_web_hunter": (
        "1. Load custom YAML signatures or curated paths via structured selectors.\n"
        "2. Align concurrency with defensive monitoring; Jaeles can be thunderous.\n"
        "3. Validate positives manually—templates vary in quality.\n"
        "4. Version-control bespoke signatures to trace assessment provenance."
    ),
    "command_injection_hunter": (
        "1. Specify injection points, transports, and tamper tiers via mapped fields.\n"
        "2. Expect operating-system level effects—sandbox the target app.\n"
        "3. Capture command outputs but avoid destructive switches (`shutdown`, etc.).\n"
        "4. Combine with SSRF testers when chaining into internal services."
    ),
    "payload_stager_builder": (
        "1. Select `payload`, `format`, `lhost`, `lport`, and encoder options documented for msfvenom.\n"
        "2. Hash every artifact, document listener expectations, and store binaries encrypted.\n"
        "3. Test stage-specific networking (NAT, egress allowlists) before engagement.\n"
        "4. Never deliver msfvenom output to unauthorised recipients."
    ),
    "credential_bruteforce": (
        "1. Provide `target`, `username`/`username_file`, `password_file`, and protocol/service selectors.\n"
        "2. Apply `threads`, `delay`, and attempt caps mandated by SOC.\n"
        "3. Stop on first success unless horizontal movement is chartered—credential stuffing may violate policy.\n"
        "4. Archive cracked creds securely; rotate them after testing."
    ),
    "gpu_hash_recovery": (
        "1. Supply `hash_file` paths and accurate `hash_type`/`attack_mode` equivalents per hashcat nomenclature.\n"
        "2. Attach wordlists/rules/masks staged on the agent—GPU jobs still need CPU preparation.\n"
        "3. Monitor thermals/power; unattended cracking can trip breakers.\n"
        "4. Document cracked passwords under evidence handling guidelines."
    ),
    "cpu_rainbow_hash_audit": (
        "1. Identify formats with hashid-style helpers before importing into John-compatible modes.\n"
        "2. Provide hash files or SAM extracts as required; rainbow tables demand local `tables_dir` mounts.\n"
        "3. Expect long runtimes—snapshot progress files.\n"
        "4. When cracking succeeds, escalate to credential rotation—not operational reuse."
    ),
    "ldap_ad_dump": (
        "1. Supply `domain`, LDAP `username`/`password` or hashes, `dc_ip`, and TLS toggles matching ldapdomaindump needs.\n"
        "2. Review HTML/JSON dumps for unintended exposure before sharing broadly.\n"
        "3. Pair with Kerberos ticketing tests only when dual-authorised.\n"
        "4. Limit scope to organisational units named in contracts."
    ),
    "generic_impacket_cli": (
        "1. Set `script` to the upstream Impacket filename and marshal arguments via structured plus `extra_args` tail.\n"
        "2. Run `impacket-spec` first when unsure how parameters map.\n"
        "3. Log every authenticated bind; Kerberos anomalies usually mean skewed clocks or wrong SPN formatting.\n"
        "4. Never mix production credentials across tenants."
    ),
    "impacket_arg_introspection": (
        "1. Populate `script` plus minimal dummy targets to retrieve help text programmatically.\n"
        "2. Use responses to hydrate safer JSON later—do not blindly paste greasy shell fragments.\n"
        "3. Cache outputs inside runbooks so operators understand mandatory switches.\n"
        "4. This route should never touch production without read-only intentions."
    ),
    "curated_impacket_enum": (
        "1. Pick the enumeration preset via `script` or module fields and include `dc_ip`, credentials, hashes, or AES keys as required.\n"
        "2. Toggle Kerberos-aware booleans deliberately—wrong combinations leak NT hash quirks.\n"
        "3. Expect large object dumps—redirect to encrypted storage.\n"
        "4. Pair results with SOC to avoid surprise lockouts."
    ),
    "curated_impacket_exec": (
        "1. Identify the transport (`wmiexec`, `psexec`, etc.) plus `command` strings reviewed by peers.\n"
        "2. Provide share paths shells and credential bundles per template—executions alter event logs drastically.\n"
        "3. Capture stdout/stderr for evidence; beware commands that reboot hosts.\n"
        "4. Escalations require explicit approval in writing."
    ),
    "robots_path_miner": (
        "1. Provide the base `url`; Parsero retrieves robots entries only.\n"
        "2. Feed discovered paths into authorised directory fuzzers—not into destructive testers without review.\n"
        "3. Some sites purposely list noisy paths—validate manually.\n"
        "4. Combine outputs with archival sources (`gau`)."
    ),
    "registration_lookup": (
        "1. Submit `domain` or IP handles via the structured WHOIS mapper.\n"
        "2. Respect registrar rate limits—use official mirrors when possible.\n"
        "3. Archive abuse contacts for escalation paths.\n"
        "4. WHOIS masking may hide ownership; note limitations in reports."
    ),
    "minimal_header_fetch": (
        "1. Provide hostnames/toggle `https` booleans depending on TLS requirements.\n"
        "2. Review CSP/HSTS/Feature-Policy quickly before deeper scanners.\n"
        "3. Follow internal data-handling guidelines when headers reveal internal IPs.\n"
        "4. Do not automate against third-party SaaS absent permission."
    ),
    "bind_style_dns": (
        "1. Enter `target` plus `record_types` lists; responses should mirror dig semantics.\n"
        "2. Use this for split-horizon troubleshooting before firing MassDNS workloads.\n"
        "3. Log resolver used if `additional_args` pins `@server` values.\n"
        "4. Large AXFR attempts belong in chartered heavy DNS jobs—not here unless exposed."
    ),
    "recursive_dns_intel": (
        "1. Configure Amass enums, wordlists, passive toggles, and output formats via JSON-first fields.\n"
        "2. Expect API quotas if passive sources authenticate—supply keys cleanly.\n"
        "3. Merge graph outputs later with Maltego/BBot pipelines when authorised.\n"
        "4. Document every API credential rotation."
    ),
    "passive_subdomain_intel": (
        "1. Populate `domain` and API-dependent toggles (`all_sources`).\n"
        "2. Run during OSINT phases; results seed active scanning once approved.\n"
        "3. Deduplicate output with shuffleDNS/wordlists cautiously.\n"
        "4. Store JSON for traceability across assessments."
    ),
    "compact_subdomains": (
        "1. Supply `domain` plus optional brute toggles referencing assetfinder quirks.\n"
        "2. Ideal for chaining into httpx/ffuf pipelines quickly.\n"
        "3. Expect compact stdout—capture for diffing engagements.\n"
        "4. Avoid hammering scopes with brute flags enabled accidentally."
    ),
    "shuffle_bruteforce": (
        "1. Feed `domains`/`domain`, `list`, resolver pools, wildcard controls, optional MassDNS bridging fields.\n"
        "2. Validate `trusted_resolver` to reduce poisoned brute-force positives.\n"
        "3. Monitor query rates for provider abuse alerts.\n"
        "4. Export JSON-compatible outputs before downstream chaining."
    ),
    "resolver_stub_storm": (
        "1. Populate `domains` corpus and resolver tuning (`resolve_count`, `threads`, hashes, flush flags).\n"
        "2. Always bound jobs—MassDNS excels at unintended self-DDoS via resolvers.\n"
        "3. Inspect logs for truncation; large wordlists spill to disk unexpectedly.\n"
        "4. Pair with PCAP only when lawful taps exist."
    ),
    "engine_subdomain_hints": (
        "1. Provide engines and parallelism fields per Sublist3r JSON schema.\n"
        "2. Expect heuristic noise—engines change frequently.\n"
        "3. Merge with authoritative DNS before claiming ownership.\n"
        "4. API failures should be retried politely."
    ),
    "traditional_dns_auditor": (
        "1. Supply domain lists, brute toggles, and recursion depth aligning with fierce/dnsenum templates.\n"
        "2. Attempt zone transfers only against assets you administer.\n"
        "3. Log wildcard detections—they influence brute noise.\n"
        "4. Pair with Resolver logs for anomalies."
    ),
    "historic_url_collectors": (
        "1. Provide `domains`/`domain`/`input` equivalents per GAU/WaybackURL connector mapping.\n"
        "2. Filter archives to scope hostnames programmatically afterwards.\n"
        "3. Archives may expose retired credentials—handle carefully.\n"
        "4. Rate-limit concurrency to obey remote archive policies."
    ),
    "multi_source_intel_crawler": (
        "1. Configure `domains`/`sources`/API keys respecting theHarvester module availability.\n"
        "2. Expect mixed-quality emails—verify via MX checks before phishing simulations.\n"
        "3. Output seeds further OSINT dashboards.\n"
        "4. Log source quotas to avoid bans."
    ),
    "advanced_wifi_lab": (
        "1. Place adapters in monitor mode upstream when required (`airmon-ng` helper routes).\n"
        "2. Provide capture paths, ESSIDs/EAP configs, handshake targets, attack modes, regulatory paperwork references.\n"
        "3. Never point attack modes at civilian infrastructure—hardware isolation only.\n"
        "4. Convert captures only within labs; distributing PMKIDs may violate telecom rules."
    ),
    "psk_crack_decrypt": (
        "1. Submit capture files passphrase lists ESSID/BSSID filters referencing aircrack/hcx tooling.\n"
        "2. Ensure captures contain complete four-way exchanges before cracking attempts waste GPU time.\n"
        "3. Document crack speeds and dictionaries for courtroom-ready notes.\n"
        "4. Decrypt PCAPs solely for evidence workflows under legal advice."
    ),
    "classic_aircrack_lab": (
        "1. Identify interface channel BSSID/client MAC selections per monitor-mode checklist.\n"
        "2. Keep antennas disconnected from production SSIDs unless emulating sanctioned evil twins.\n"
        "3. Log injection counts to explain RF impacts.\n"
        "4. Pair `aireplay-ng` bursts with humane scheduling—Wi-Fi disruptions alarm users instantly."
    ),
    "passive_rf_sensor": (
        "1. Provide interface definitions logging directories and drone alert preferences per kismet packaging.\n"
        "2. Primarily passive—respect privacy expectations on shared spectrum.\n"
        "3. Expect huge PCAP volumes; prune routinely.\n"
        "4. Correlate sightings with authorised asset inventories only."
    ),
    "binary_triage_util": (
        "1. Provide `binary`, `file_path`, or CLI-equivalent selectors for quick static insight.\n"
        "2. Use triage utilities before heavyweight Ghidra/autopsy timelines.\n"
        "3. Outputs are succinct—combine with checklist reporting.\n"
        "4. Malware artefacts remain hazardous—sandbox hosts accordingly."
    ),
    "forensic_carvers": (
        "1. Point `input_file`/`image_path`/`output_dir` fields at sanctioned evidence stores.\n"
        "2. Choose carving signatures conservatively—broad signatures balloon storage.\n"
        "3. Keep chain-of-custody notes for every exported file.\n"
        "4. Some carvers overwrite slack space—snapshot images first."
    ),
    "rop_libc_tooling": (
        "1. Provide `binary`, `libc_path`, architectures, libc IDs, gadgets filters per tool.\n"
        "2. Validate gadget addresses on target libc builds—offsets shift with patches.\n"
        "3. Document gadget chains reviewed by peers.\n"
        "4. Keep exploit artifacts confidential."
    ),
    "deep_binary_analysis": (
        "1. Pass file paths macros scripts analysis toggles aligning with gdb/radare2/ghidra headless wrappers.\n"
        "2. Long analyses need `timeout` fields—coordinate with infra.\n"
        "3. Store project directories on encrypted volumes.\n"
        "4. Symbolic backends may spin CPU—quota jobs fairly."
    ),
    "exploit_scaffolding": (
        "1. Embed pwntools/angr scripting via `script_content`; pair with `target_host`/`target_port` or local `target_binary`.\n"
        "2. `pwninit` requires libc/ld pairings—supply accurate versions.\n"
        "3. Never point scaffolding at production—use CTF nets or clones.\n"
        "4. Record exploit randomness seeds for deterministic replay."
    ),
    "golang_link_spider": (
        "1. Seed URLs depth forms robots toggles akin to hakrawler semantics.\n"
        "2. Ideal for breadth-first inventories before katana depths.\n"
        "3. Limit forms parsing when destructive POST risk exists.\n"
        "4. Merge with archival sources when optional Wayback flags exist."
    ),
    "orchestrated_recon": (
        "1. Populate `targets`, `heartbeat`, timeouts, directories, modular toggles referencing AutoRecon packaging.\n"
        "2. Expect multi-hour timelines—checkpoint `output_dir`.\n"
        "3. Use `additional_args` only for ancillary modules spelled out by runbooks.\n"
        "4. Verify each bundled tool inside AutoRecon is individually approved."
    ),
    "graphql_abuse": (
        "1. Provide `graphql_url`, depth/query toggles introspection booleans authorised by schema owners.\n"
        "2. Watch for unstable nested queries—they can degrade services even in labs.\n"
        "3. Pair results with JWT analyser tooling when hybrid APIs exist.\n"
        "4. Record query text for remediation teams verbatim."
    ),
    "jwt_crypto_tests": (
        "1. Paste `jwt_token`, optional `secrets` dictionaries, attacker URLs referencing replay sinks.\n"
        "2. Validate algorithm downgrade attempts only on disposable sessions.\n"
        "3. Document each tampered token hashed for evidentiary continuity.\n"
        "4. Stop brute forcing secrets when charters cap attempts."
    ),
    "schema_policy_review": (
        "1. Supply `schema_url`/`swagger_url` plus parsers (`schema_type`).\n"
        "2. Static analysis surfaces risky operations—not runtime bugs.\n"
        "3. Cross-check findings with penetration tests afterwards.\n"
        "4. Export JSON for downstream Schemathesis planning."
    ),
    "param_discovery_active": (
        "1. Provide base URLs methods delay threads wordlists aligning with Arjun.\n"
        "2. Use stabilisation toggles when applications are noisy.\n"
        "3. Feed discoveries into authorised fuzz pipelines.\n"
        "4. Stop if application owners report instability."
    ),
    "param_historic_mining": (
        "1. Tie `domains` exclusions depth flags to archival mining expectations.\n"
        "2. Validate parameters still exist live before exploitation.\n"
        "3. Respect archive licensing.\n"
        "4. Deduplicate with `uro` pipelines."
    ),
    "hidden_param_diffing": (
        "1. Submit baseline URLs payloads headers bodies per x8 template.\n"
        "2. Interpret diffs cautiously—CDNs introduce noise.\n"
        "3. Pair results with authorised ffuf bursts.\n"
        "4. Keep concurrency sane on fragile APIs."
    ),
    "url_pipeline_transform": (
        "1. Pipe newline URLs via `stdin` equivalent fields documented for qsreplace/anew/uro.\n"
        "2. Mark replacement tokens distinctly when prepping ffuf placeholders.\n"
        "3. Use `uro` to dedupe monstrous crawler outputs feeding nuclei templates.\n"
        "4. Document pipeline ordering for reproducibility."
    ),
    "memory_forensics": (
        "1. Specify `memory_file`, Volatility-style `profile`/`plugin`, and plugin lists per route.\n"
        "2. Validate profile selection—incorrect profiles produce nonsense.\n"
        "3. Store plugin outputs encrypted; RAM captures hold secrets wholesale.\n"
        "4. Coordinate runtime with forensic leads before running destructive plugins."
    ),
    "stego_lab": (
        "1. Provide cover/embed files passphrase actions keyed to steghide/stegsolve/zsteg/outguess flows.\n"
        "2. Outputs may be ambiguous—combine with entropy analysis elsewhere.\n"
        "3. Carriers might be copyrighted—handle distribution carefully.\n"
        "4. Document attempted transforms for regulators."
    ),
    "metadata_mutator": (
        "1. Submit `file_path`, tag selections, recursion toggles aligning with ExifTool wrappers.\n"
        "2. Avoid writing GPS metadata creep into leaked evidence.\n"
        "3. Use read-only semantics unless charter allows mutation.\n"
        "4. Keep backups prior to rewriting metadata."
    ),
    "length_extension_lab": (
        "1. Specify secret length original message append bytes hash algorithm via mapped fields.\n"
        "2. Validate forged signatures offline before replaying downstream.\n"
        "3. Pair with cryptographic reviews—mistakes degrade trust narratives.\n"
        "4. Document assumptions about padding oracles explicitly."
    ),
    "cloud_posture_graph": (
        "1. Populate cloud profile/session fields provider flags services directories per scout/pacu/cloudmapper wrappers.\n"
        "2. Expect large IAM graphs—narrow services first.\n"
        "3. Export HTML/JSON responsibly; URLs may contain account identifiers.\n"
        "4. Rotate cloud keys after engagements."
    ),
    "policy_compliance_scan": (
        "1. Provide kubeconfig paths image refs benchmark ids directories matching Trivy/Checkov/kube-bench/Clair/Falco wrappers.\n"
        "2. Align severities/report formats with SOC ingestion pipelines.\n"
        "3. Remediation tips require owner teams—don't auto-patch.\n"
        "4. Some scans mutate nothing; others exec inside clusters—confirm blast radius."
    ),
    "kubernetes_redteam": (
        "1. Deliver cluster entrypoints hunters modules per kube-hunter route.\n"
        "2. Active hunters may disrupt workloads—coordinate with platform SRE.\n"
        "3. Store JSON outputs for ticketing.\n"
        "4. Never aim at unmanaged multi-tenant clusters."
    ),
    "bbot_osint_engine": (
        "1. Hydrate YAML/JSON `parameters` seeds events modules flags per BBot contract.\n"
        "2. Module fan-out behaves like crawler swarms throttle aggressively.\n"
        "3. Archive graph-friendly exports for authorised analysts only.\n"
        "4. Validate API tokens per module before enabling."
    ),
    "netexec_multi_protocol": (
        "1. Specify `protocol`, `target`, creds hashes modules command macros.\n"
        "2. Many modules escalate quickly—tie each action to written objectives.\n"
        "3. Expect Defender correlation IDs referencing your source IP/time.\n"
        "4. Use jump boxes dedicated to engagements."
    ),
    "ruby_winrm_shell": (
        "1. Populate `username`, optional `password`/`hash`, `target_ip`, TLS toggles referencing Evil-WinRM mapping.\n"
        "2. Interactive shells behave like SSH—everything logs server-side.\n"
        "3. Upload pathways may trip AV document binaries.\n"
        "4. Close sessions politely to flush transcripts."
    ),
    "metasploit_console": (
        "1. Identify `module` plus `options` dict mirroring msfconsole `set` verbs.\n"
        "2. Dry-run payloads on disposable VMs first.\n"
        "3. Watch job output for unstaged timeouts—handlers must be reachable legally.\n"
        "4. Never cross legal boundaries via auto-run scripts."
    ),
    "exploitdb_lookup": (
        "1. Provide search strings aligning with exploit-db offline mirrors bundled on NyxStrike.\n"
        "2. Exploit PoCs may be unreliable—audit code before executing.\n"
        "3. Record CVE references for Responsible Disclosure trackers.\n"
        "4. Keep mirrors updated per compliance policy."
    ),
    "fingerprint_blitz": (
        "1. Supply newline hosts/toggle aggression fields per WhatWeb wrappers.\n"
        "2. Useful for coarse stack discovery ahead of scanners.\n"
        "3. False positives abound—sanity-check with manual headers.\n"
        "4. Rate-limit concurrency on SaaS fronts."
    ),
    "gui_web_scanner": (
        "1. Configure `target`, API listener keys, concurrency pages scan policies per Burp/ZAP automation façade.\n"
        "2. Headless scanners still mutate state validate CSRF safeguards.\n"
        "3. Export reports into encrypted evidence stores promptly.\n"
        "4. Provide unique API keys per engagement."
    ),
    "http_framework_replay": (
        "1. Choose HTTP verbs headers bodies cookies proxies replay toggles enumerated for this route.\n"
        "2. Ideal ad hoc verifier before scripting pipelines.\n"
        "3. Manual replays hitting POST endpoints may write data throttle accordingly.\n"
        "4. Document every transactional ID touched."
    ),
    "rest_surface_mapper": (
        "1. Pair `base_url` with verbs wordlists endpoints lists rate controls.\n"
        "2. Treat discovered routes as tentative until authenticated testing proves reachability.\n"
        "3. Stop fuzzing destructive admin verbs unless explicitly chartered.\n"
        "4. Merge output with schema analyzers downstream."
    ),
    "openapi_property_fuzz": (
        "1. Configure schema URLs or uploaded OpenAPI/GraphQL descriptors plus phased execution (`phases`), workers, rate limiting, timeouts, "
        "`max_examples`, include/exclude `operation_id` guards, check lists, and report formats demanded by SOC pipelines.\n"
        "2. Start with narrower phases (`examples` only) against staging tenants before unleashing combined coverage + fuzz states.\n"
        "3. Inspect Hypothesis shrinking logs—they pinpoint minimal failing sequences worthy of CVE-style write-ups.\n"
        "4. Export SARIF/HTML/JUnit artefacts into ticketing with severity annotations summarising reproducible payloads."
    ),
    "username_osint": (
        "1. Provide handles timeout concurrency flags Sherlock expects.\n"
        "2. Social hits may belong to unrelated users verify manually.\n"
        "3. Respect site ToS—even OSINT engagements need legal review sometimes.\n"
        "4. Cache JSON for privacy reviews before wider sharing."
    ),
    "osint_platform": (
        "1. Load workspace modules transforms API keys complying with Spiderfoot/Recon-ng/Maltego licensing.\n"
        "2. Longitudinal jobs (`poll_interval`) may take hours—checkpoint state.\n"
        "3. Graph exports can leak third-party identifiers handle per GDPR charters.\n"
        "4. Disable modules that scrape disallowed jurisdictions."
    ),
    "llmnr_poisoning": (
        "1. Specify `interface` poison duration analyse toggles impersonation safeguards.\n"
        "2. Keep responder on segmented VLAN taps—broadcast domains amplify damage.\n"
        "3. Capture hashes securely; cracking belongs to chartered phases.\n"
        "4. Stop runs immediately if unintended clients attach."
    ),
    "disk_case_workflow": (
        "1. Point `image_path`/`directory`/`case_name`/`project_name` fields at sanctioned evidence lockers.\n"
        "2. Long-running ingestion jobs need disk quotas—coordinate with infra.\n"
        "3. Exported timelines may contain privileged communications restrict viewers.\n"
        "4. Chain SleuthKit outputs into Autopsy dashboards when routes split duties."
    ),
    "packet_capture_analysis": (
        "1. Provide PCAP paths capture/display filters exporters stats toggles aligning with tcpdump/tshark/wireshark packaging.\n"
        "2. Expect sensitive payloads minimise distribution encrypt everything.\n"
        "3. Follow lawful intercept mandates when analysing customer traffic mirrors.\n"
        "4. GUI Wireshark stays human-driven headless watchers feed SIEM deltas."
    ),
    "sql_cli_probe": (
        "1. Supply connection strings databases SQL fragments credentials per mysql/sqlite wrappers.\n"
        "2. Dry-run selects before mutating—even read queries may lock rows.\n"
        "3. Log every statement for auditors.\n"
        "4. Use disposable databases whenever feasible."
    ),
    "netbios_sweeper": (
        "1. Provide subnet/CIDR/IP lists plus timing fields accepted by `nbtscan`-style wrappers on the bastion.\n"
        "2. Expect coarse NetBIOS names/workgroups—not a substitute for SMB authentication testing.\n"
        "3. Pair positive hits with `enum4linux(-ng)`, `rpcclient`, or `smbmap` once credentialed access is chartered.\n"
        "4. Broadcast scopes can overwhelm small offices—obtain SOC approval before broad sweeps."
    ),
    "bettercap_platform": (
        "1. Put the chosen `interface` into monitor/AP modes upstream if caplets assume promiscuity; load `caplet` payloads only after validating RF containment.\n"
        "2. Feed targets (BSSIDs/clients/IP ranges), proxy toggles, and script hooks expected by bundled bettercap integrations.\n"
        "3. Expect JSON/event streams documenting MITM primitives—everything touched by transparent proxies generates legal exposure unless isolated.\n"
        "4. Compare against classic `aireplay-ng` workflows: bettercap unifies transports but introduces heavier dependence on agent drivers."
    ),
    "samba_rpc_macros": (
        "1. Provide `target`, authentication material (password, `hashes`, AES keys, `dc_ip`, Kerberos booleans) before pasting `commands` macros recognised by `rpcclient`.\n"
        "2. Each macro (`enumdomusers`, `querydominfo`, etc.) should correspond to an operator-approved action; avoid destructive RPC unless explicitly chartered.\n"
        "3. Expect Samba client stderr alongside results—Kerberos clock skew and SPN typos are the usual failure modes.\n"
        "4. Treat output as sensitive AD intelligence; redact before ticketing and pair with `ldapdomaindump` for coverage."
    ),
    "generic_connector": (
        "1. Cross-check the catalogue fields in the Execute modal—they map 1:1 into the NyxStrike JSON schema for this slug.\n"
        "2. Populate required keys first omit optional blanks so the proxy body stays minimal.\n"
        "3. Use `additional_args` only after confirming the bastion-side wrapper honours the extra switches.\n"
        "4. Read stdout/err plus runner metadata correlating timestamps with SIEM ingestion rules."
    ),
}


def clustered_usage(tool: str, endpoint: str) -> str:
    key = cluster_for(tool)
    body = _CLUSTER_USAGE.get(key) or _CLUSTER_USAGE["generic_connector"]
    if "{endpoint}" in body:
        return body.format(endpoint=endpoint)
    hdr = f"CipherStrike `{tool}` executes against `{endpoint}` via POST JSON envelopes assembled in the Execute modal.\n\n"
    return hdr + body


def compose_long_description(lead: str, tool: str, category: str, endpoint: str) -> str:
    p2, p3, p4 = supplement_for(tool, category)
    transport = (
        f"CipherStrike transmits the JSON envelope to `{endpoint}`; NyxStrike performs final validation, "
        "then shells out or calls the bundled integration advertised for this catalogue id."
    )
    return "\n\n".join([lead.strip(), p2.strip(), p3.strip(), p4.strip(), transport.strip()])