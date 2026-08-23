"""
server_core/adk/state.py

Structured State and Knowledge Graph for Google ADK in Vrika Agent.
Maintains typed entity state across turns (targets, open ports, technologies, CVEs, attack paths).
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DiscoveredFinding(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    title: str
    severity: str = "medium"  # critical | high | medium | low | info
    cve_id: Optional[str] = None
    target: str = ""
    endpoint: str = ""
    description: str = ""
    proof: str = ""
    tool_source: str = ""


class TargetKnowledgeState(BaseModel):
    """Structured knowledge graph for active target."""
    target_url: str = ""
    hostnames: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    open_ports: Dict[str, List[int]] = Field(default_factory=dict)  # {"10.0.0.1": [80, 443]}
    technologies: List[str] = Field(default_factory=list)
    discovered_endpoints: List[str] = Field(default_factory=list)
    findings: List[DiscoveredFinding] = Field(default_factory=list)
    executed_tools: List[str] = Field(default_factory=list)

    def to_compact_context(self) -> str:
        """Render high-density structured prompt section for LLM turns."""
        lines = []
        if self.target_url:
            lines.append(f"Target: {self.target_url}")
        if self.hostnames:
            lines.append(f"Hostnames: {', '.join(sorted(set(self.hostnames))[:10])}")
        if self.ips:
            lines.append(f"IP Addresses: {', '.join(sorted(set(self.ips))[:5])}")
        if self.open_ports:
            ports_summary = ", ".join(f"{h}: {p}" for h, p in list(self.open_ports.items())[:5])
            lines.append(f"Open Ports: {ports_summary}")
        if self.technologies:
            lines.append(f"Technologies: {', '.join(sorted(set(self.technologies))[:10])}")
        if self.discovered_endpoints:
            lines.append(f"Discovered Endpoints ({len(self.discovered_endpoints)}): {', '.join(self.discovered_endpoints[:8])}")
        if self.findings:
            sev_counts = {}
            for f in self.findings:
                sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
            sev_summary = ", ".join(f"{s.upper()}: {c}" for s, c in sev_counts.items())
            lines.append(f"Security Findings ({len(self.findings)}): {sev_summary}")
            for f in self.findings[:5]:
                lines.append(f"  - [{f.severity.upper()}] {f.title} ({f.target})")
        if not lines:
            return ""
        return "[Active Target Knowledge Snapshot]\n" + "\n".join(lines)


class VrikaAgentState(BaseModel):
    """Top-level agent state container."""
    session_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    knowledge: TargetKnowledgeState = Field(default_factory=TargetKnowledgeState)
    active_phase: str = "reconnaissance"  # recon | scanning | exploitation | reporting | conversational
    tool_execution_mode: str = "ask_permission"  # ask_permission | auto_accept
    last_user_message: str = ""
    recent_context: str = ""
    rolling_summary: str = ""


# ---------------------------------------------------------------------------
# Automated State Extraction from Tool Outputs
# ---------------------------------------------------------------------------

def extract_state_from_tool_output(
    state: TargetKnowledgeState,
    tool_name: str,
    output_data: Any,
) -> None:
    """Parse tool output and merge discoveries into the structured target knowledge state."""
    tool_clean = tool_name.strip().lower()
    if tool_clean not in state.executed_tools:
        state.executed_tools.append(tool_clean)

    text = str(output_data) if not isinstance(output_data, str) else output_data
    if isinstance(output_data, dict):
        text = json.dumps(output_data)

    # 1. Extract URLs
    urls = re.findall(r"https?://[a-zA-Z0-9\.\-_]+(?::\d+)?(?:/[^\s\"\'<>]*)?", text)
    for u in urls:
        if not state.target_url and "http" in u:
            state.target_url = u
        if len(state.discovered_endpoints) < 50 and u not in state.discovered_endpoints:
            state.discovered_endpoints.append(u)

    # 2. Extract IPv4
    ips = re.findall(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", text)
    for ip in ips:
        if not ip.startswith("127.") and not ip.startswith("0.") and ip not in state.ips:
            state.ips.append(ip)

    # 3. Extract Open Ports (Nmap / Masscan / Rustscan)
    if tool_clean in ("nmap", "masscan", "rustscan", "httpx"):
        port_matches = re.findall(r"(\d{1,5})/(?:tcp|udp)\s+open", text, re.IGNORECASE)
        if port_matches:
            host_key = state.ips[0] if state.ips else (state.target_url or "target")
            ports = [int(p) for p in port_matches if 0 < int(p) <= 65535]
            existing = state.open_ports.get(host_key, [])
            state.open_ports[host_key] = sorted(list(set(existing + ports)))

    # 4. Extract Technologies (WhatWeb, Wafw00f, Httpx)
    if tool_clean in ("whatweb", "wafw00f", "httpx"):
        tech_matches = re.findall(r"(?:Detected|Powered by|Server|Framework|WAF):\s*([a-zA-Z0-9\-_ /]+)", text, re.IGNORECASE)
        for t in tech_matches:
            clean_t = t.strip()
            if clean_t and clean_t not in state.technologies and len(clean_t) < 40:
                state.technologies.append(clean_t)

    # 5. Extract Vulnerabilities (Nuclei, Nikto, Vulnx, SQLmap)
    if tool_clean in ("nuclei", "nikto", "vulnx", "sqlmap", "dalfox"):
        nuclei_matches = re.findall(r"\[([a-zA-Z0-9\-_]+)\]\s+\[(critical|high|medium|low|info)\]\s+(https?://[^\s]+)", text, re.IGNORECASE)
        for template_id, sev, target_ep in nuclei_matches:
            f = DiscoveredFinding(
                title=f"Vulnerability ({template_id})",
                severity=sev.lower(),
                target=target_ep,
                endpoint=target_ep,
                tool_source=tool_clean,
            )
            state.findings.append(f)
