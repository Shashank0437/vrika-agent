"""
server_core/adk/agents.py

Multi-Agent Definitions and Orchestration for Google ADK in Vrika.
Defines Supervisor, Recon, Vulnerability Assessment, Cloud, and Reporting Agents.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SpecialistAgentConfig:
    """Configuration definition for an ADK specialist agent."""
    def __init__(
        self,
        name: str,
        role: str,
        description: str,
        default_tools: List[str],
    ) -> None:
        self.name = name
        self.role = role
        self.description = description
        self.default_tools = default_tools


# Registered Domain Specialists
SPECIALIST_REGISTRY: Dict[str, SpecialistAgentConfig] = {
    "web_recon": SpecialistAgentConfig(
        name="ReconSpecialist",
        role="recon",
        description="Reconnaissance, subdomain enumeration, port scanning, and technology fingerprinting",
        default_tools=["httpx", "nmap", "subfinder", "whatweb", "wafw00f", "gau"],
    ),
    "network_recon": SpecialistAgentConfig(
        name="NetworkReconSpecialist",
        role="recon",
        description="Network port scanning, service discovery, and banner grabbing",
        default_tools=["nmap", "masscan", "rustscan", "httpx"],
    ),
    "web_vuln": SpecialistAgentConfig(
        name="VulnerabilitySpecialist",
        role="web_vuln",
        description="Web application vulnerability scanning, SQLi, XSS, and template scans",
        default_tools=["nuclei", "nikto", "sqlmap", "dalfox", "wafw00f"],
    ),
    "cloud": SpecialistAgentConfig(
        name="CloudSecuritySpecialist",
        role="cloud",
        description="Cloud infrastructure, IAM, S3, and container security audits",
        default_tools=["prowler", "trivy"],
    ),
    "reporting": SpecialistAgentConfig(
        name="ReportingSpecialist",
        role="reporting",
        description="Formal penetration testing executive summaries and PDF report generation",
        default_tools=["penetration-report"],
    ),
}


class VrikaOrchestrator:
    """Fallback planner for the ADK turn orchestrator.

    This is deliberately deterministic and catalog-aware.  It is used only when
    the model router is unavailable or produces an unusable operational plan;
    it must never replace the model router's contextual tool selection.
    """

    @staticmethod
    def classify_and_route(
        user_message: str,
        context_str: str = "",
        catalog_tools: Optional[List[Dict[str, Any]]] = None,
        max_tools: int = 12,
    ) -> Dict[str, Any]:
        """Return a safe, catalog-filtered fallback route.

        ``catalog_tools`` is the caller's authorization boundary.  Never emit a
        tool that was not offered by that catalog.
        """
        text_lower = user_message.lower().strip()
        combined_text = f"{context_str}\n{user_message}".lower()

        catalog_names = [
            str(tool.get("name") or "").strip()
            for tool in (catalog_tools or [])
            if isinstance(tool, dict) and str(tool.get("name") or "").strip()
        ]
        catalog_by_lower = {name.lower(): name for name in catalog_names}

        def available(names: List[str]) -> List[str]:
            selected: List[str] = []
            for name in names:
                canonical = catalog_by_lower.get(name.lower())
                if canonical and canonical not in selected:
                    selected.append(canonical)
                if len(selected) >= max_tools:
                    break
            return selected

        def matching_tools(keywords: List[str]) -> List[str]:
            scored: List[tuple[int, str]] = []
            for tool in catalog_tools or []:
                if not isinstance(tool, dict):
                    continue
                name = str(tool.get("name") or "").strip()
                if not name:
                    continue
                haystack = f"{name} {tool.get('desc') or ''}".lower()
                score = sum(1 for word in keywords if word in haystack)
                if score:
                    scored.append((score, name))
            return [name for _, name in sorted(scored, key=lambda item: (-item[0], item[1]))[:max_tools]]

        # 0. Check for explicit tool name mentions first (e.g. "run nmap on ...", "use nuclei ...")
        for tname in ["nmap", "rustscan", "nuclei", "nikto", "sqlmap", "httpx", "subfinder", "whatweb", "wafw00f", "dalfox", "gobuster", "ffuf", "dirb", "masscan", "penetration-report"]:
            if re.search(r"\b" + re.escape(tname) + r"\b", text_lower):
                matched = available([tname])
                if matched:
                    cat = "reporting" if tname == "penetration-report" else "network_recon" if tname in ("nmap", "rustscan", "masscan") else "web_vuln" if tname in ("nuclei", "nikto", "sqlmap", "dalfox") else "web_recon"
                    return {
                        "intent": "operational",
                        "category": cat,
                        "tool_names": matched,
                        "reply": "",
                    }

        # 1. Check for PDF / Report request
        if any(w in text_lower for w in ["report", "pdf", "writeup", "write-up", "executive summary", "document findings"]):
            return {
                "intent": "operational",
                "category": "reporting",
                "tool_names": available(["penetration-report"]),
                "reply": "",
            }

        # 2. Check for Reconnaissance / Port Scan
        if any(w in text_lower for w in ["port scan", "ports", "subdomain", "subfinder", "httpx", "recon", "fingerprint", "whatweb"]):
            return {
                "intent": "operational",
                "category": "network_recon" if any(w in text_lower for w in ["port", "masscan", "rustscan"]) else "web_recon",
                "tool_names": available(["nmap", "httpx", "whatweb", "wafw00f", "subfinder", "masscan", "rustscan"]),
                "reply": "",
            }


        # 3. Check for Comprehensive Pentest / URL Vulnerability Scan
        if ("http://" in user_message or "https://" in user_message or "canplus" in user_message or "target" in combined_text) and any(
            w in text_lower for w in ["pentest", "vapt", "scan", "test", "vuln", "vulnerability", "audit", "assess", "check"]
        ):
            return {
                "intent": "operational",
                "category": "web_vuln",
                "tool_names": available(["wafw00f", "httpx", "nuclei", "nikto", "whatweb", "ffuf", "dalfox", "sqlmap"]),
                "reply": "",
            }

        # 4. Check for pure conversational / informational
        if len(text_lower.split()) <= 3 and any(w in text_lower for w in ["hi", "hello", "hey", "who are you", "help", "thanks"]):
            return {
                "intent": "conversational",
                "category": "",
                "tool_names": [],
                "reply": "Hello! I am Vrika, your automated offensive security and penetration testing AI assistant. How can I assist with your security assessment today?",
            }

        # 5. Default operational fallback if target is present
        if "http://" in combined_text or "https://" in combined_text or "scan" in text_lower:
            return {
                "intent": "operational",
                "category": "web_vuln",
                "tool_names": matching_tools(["http", "vuln", "scan", "recon", "nuclei", "nikto"]),
                "reply": "",
            }

        return {
            "intent": "conversational",
            "category": "",
            "tool_names": [],
            "reply": "",
        }
