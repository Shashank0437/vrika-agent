"""
server_core/adk/agents.py

Multi-Agent Definitions and Orchestration for Google ADK in Vrika.
Defines Supervisor, Recon, Vulnerability Assessment, Cloud, and Reporting Agents.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from server_core.adk.state import VrikaAgentState
from server_core.adk.prompts import build_consolidated_system_prompt
from server_core.adk.tools import get_adk_tools_for_names

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
    """Google ADK Orchestrator for intent routing, sub-agent delegation, and prompt composition."""

    @staticmethod
    def classify_and_route(
        user_message: str,
        context_str: str = "",
        catalog_tools: Optional[List[Dict[str, Any]]] = None,
        max_tools: int = 12,
    ) -> Dict[str, Any]:
        """Classify operator request and determine intent, category, and tool shortlist."""
        text_lower = user_message.lower().strip()
        combined_text = f"{context_str}\n{user_message}".lower()

        # 1. Check for PDF / Report request
        if any(w in text_lower for w in ["report", "pdf", "writeup", "write-up", "executive summary", "document findings"]):
            return {
                "intent": "operational",
                "category": "reporting",
                "tool_names": ["penetration-report"],
                "reply": "",
            }

        # 2. Check for Reconnaissance / Port Scan
        if any(w in text_lower for w in ["nmap", "port scan", "ports", "subdomain", "subfinder", "httpx", "recon", "fingerprint", "whatweb"]):
            return {
                "intent": "operational",
                "category": "web_recon",
                "tool_names": ["httpx", "nmap", "whatweb", "wafw00f", "subfinder"][:max_tools],
                "reply": "",
            }

        # 3. Check for Comprehensive Pentest / URL Vulnerability Scan
        if ("http://" in user_message or "https://" in user_message or "canplus" in user_message or "target" in combined_text) and any(
            w in text_lower for w in ["pentest", "vapt", "scan", "test", "vuln", "vulnerability", "audit", "assess", "check"]
        ):
            return {
                "intent": "operational",
                "category": "web_vuln",
                "tool_names": ["wafw00f", "httpx", "nuclei", "nikto"][:max_tools],
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
                "tool_names": ["httpx", "nuclei", "wafw00f"][:max_tools],
                "reply": "",
            }

        return {
            "intent": "conversational",
            "category": "",
            "tool_names": [],
            "reply": "",
        }
