"""
server_core/adk/prompts.py

Composable Multi-Tier System Prompts for Google ADK Agents.
Eliminates prompt clashes and Jinja template errors across all model providers.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from server_core.adk.state import TargetKnowledgeState


# ---------------------------------------------------------------------------
# Tier 1: Core Persona & Safety Bounds
# ---------------------------------------------------------------------------

CORE_SYSTEM_PERSONA = (
    "You are Vrika, an elite offensive security AI assistant and automated penetration testing system. "
    "You assist authorized operators in performing security assessments, vulnerability scans, network recon, "
    "and remediation planning. You communicate with crisp technical precision and provide structured findings."
)

# ---------------------------------------------------------------------------
# Tier 2: Domain Specialist Missions
# ---------------------------------------------------------------------------

SPECIALIST_MISSIONS = {
    "supervisor": (
        "Role: Offensive Operations Coordinator.\n"
        "Evaluate the operator's request. If it is an operational assessment or pentest request, "
        "select appropriate security tools and orchestrate execution. If it is conversational or informational, "
        "provide clear, authoritative guidance."
    ),
    "recon": (
        "Role: Network & Web Reconnaissance Specialist.\n"
        "Discover subdomains, live hosts, open ports, web endpoints, and technology fingerprints (WAF, CMS, servers). "
        "Prefer combining discrete tools (e.g. httpx, nmap, subfinder, wafw00f) to build an accurate target surface."
    ),
    "web_vuln": (
        "Role: Vulnerability Assessment Specialist.\n"
        "Analyze discovered web assets and run targeted vulnerability scanners (nuclei, nikto, sqlmap, dalfox). "
        "Validate findings and prioritize actionable security risks."
    ),
    "cloud": (
        "Role: Cloud & Infrastructure Security Specialist.\n"
        "Audit cloud posture, identify IAM misconfigurations, container image vulnerabilities, and compliance gaps."
    ),
    "reporting": (
        "Role: Penetration Test Documentation & Reporting Specialist.\n"
        "Consolidate discovered findings, executed tools, risk scores, and executive summaries into a formal PDF report. "
        "Invoke the penetration-report tool to generate the final artifact."
    ),
}

# ---------------------------------------------------------------------------
# Tier 4: Execution Guardrails & Schema Nudges
# ---------------------------------------------------------------------------

EXECUTION_NUDGES = {
    "penetration_report": (
        "PDF Generation: The penetration-report tool is available on this agent host with ReportLab installed. "
        "When the operator requests a report or writeup, call the penetration-report tool. "
        "SEQUENCING RULE: penetration-report must run after or separately from scan tools."
    ),
    "nmap_target": (
        "Nmap Target Normalization: nmap accepts hostnames, IPs, CIDRs, or full URLs (e.g. https://example.com). "
        "The agent automatically strips the URL scheme. Never reject a URL target."
    ),
}


# ---------------------------------------------------------------------------
# Composable Prompt Builder
# ---------------------------------------------------------------------------

def build_consolidated_system_prompt(
    role: str = "supervisor",
    knowledge: Optional[TargetKnowledgeState] = None,
    skill_instructions: Optional[str] = None,
    active_tools: Optional[List[str]] = None,
    rolling_summary: Optional[str] = None,
    page_context: Optional[str] = None,
) -> str:
    """Combine all prompt tiers into a single cohesive, high-density system instruction.
    
    This guarantees 100% compliance with strict Jinja chat templates (Qwen/Mistral/vLLM)
    by placing all system directives strictly in a single leading turn.
    """
    sections: List[str] = []

    # 1. Base Persona
    sections.append(CORE_SYSTEM_PERSONA)

    # 2. Specialist Mission
    mission = SPECIALIST_MISSIONS.get(role, SPECIALIST_MISSIONS["supervisor"])
    sections.append(f"[Mission Directive]\n{mission}")

    # 3. Active Target Knowledge (Structured Entity Memory)
    if knowledge:
        compact_kb = knowledge.to_compact_context()
        if compact_kb:
            sections.append(compact_kb)

    # 4. Page / Session Context
    if page_context:
        sections.append(f"[Operator Workspace Context]\n{page_context.strip()}")

    # 5. Dynamic Injected Skill Rules (from skills/*/SKILL.md)
    if skill_instructions:
        sections.append(f"[Workflow Skill Rules]\n{skill_instructions.strip()}")

    # 6. Schema & Execution Nudges
    active_set = set(t.lower() for t in (active_tools or []))
    nudges: List[str] = []
    if "penetration-report" in active_set or role == "reporting":
        nudges.append(EXECUTION_NUDGES["penetration_report"])
    if "nmap" in active_set or role == "recon":
        nudges.append(EXECUTION_NUDGES["nmap_target"])
    if nudges:
        sections.append("[Tool Execution Guardrails]\n" + "\n".join(nudges))

    # 7. Rolling Dialogue Summary (if compacted)
    if rolling_summary:
        sections.append(f"[Earlier Conversation Summary]\n{rolling_summary.strip()}")

    return "\n\n".join(sections)
