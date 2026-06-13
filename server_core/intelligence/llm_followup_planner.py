"""
Context-based AI follow-up planner for Vrika agent chat sessions.

Uses session intelligence + chat context instead of NyxStrike sess_* IDs.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from tool_registry import TOOLS

from server_core.intelligence.llm_attack_chain_planner import _heuristic_phases, _parse_step_params
from server_core.llm_agent import _parse_followup

logger = logging.getLogger(__name__)

_FOLLOWUP_SYSTEM_PROMPT = """\
You are an expert penetration tester producing a prioritised follow-up action plan.

You will be given:
  - A target and objective from a completed or in-progress security assessment
  - Risk level and executive summary
  - Tools already executed
  - Evidence-backed findings (severity, tool source, details)
  - Optional chat context with tool outputs

Your task is to produce a SHORT, EXECUTABLE follow-up workflow (3–8 steps) using
only real security tools that add value beyond what already ran.

Output format (emit each applicable line):
  SUMMARY: <one paragraph rationale for the follow-up plan>
  STEP: <tool_name> | PARAMS: <key=val,key2=val2> | REASON: <one sentence rationale>

Rules:
  - Emit SUMMARY exactly once.
  - Emit 3–8 STEP: lines ordered by priority (highest impact first).
  - STEP tool_name must be exact lowercase identifiers from the NyxStrike registry
    (e.g. nuclei, sqlmap, dalfox, gobuster, ffuf, nikto, subfinder, nmap).
  - PARAMS: comma-separated key=value pairs; use the session target for target/url/domain.
  - Do NOT repeat a tool that already ran unless parameters are meaningfully different.
  - Reference actual findings, ports, paths, and services from the context.
  - Do NOT call tools; planning only.
"""


def _format_findings(findings: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    for f in findings[:25]:
        if not isinstance(f, dict):
            continue
        name = str(f.get("name") or f.get("vuln_name") or "finding").strip()
        sev = str(f.get("severity") or "INFO").upper()
        tool = str(f.get("source_tool") or "").strip()
        details = str(f.get("details") or f.get("description") or "").strip()[:300]
        prefix = f"  [{sev}] {name}"
        if tool:
            prefix += f" (via {tool})"
        if details:
            prefix += f": {details}"
        lines.append(prefix)
    return "\n".join(lines) if lines else "  (no structured findings recorded)"


def _parsed_to_workflow_steps(
    parsed_steps: List[Dict[str, Any]],
    *,
    target: str,
    tools_executed: List[str],
) -> List[Dict[str, Any]]:
    executed_lower = {str(t).strip().lower() for t in tools_executed if str(t).strip()}
    out: List[Dict[str, Any]] = []
    for raw in parsed_steps:
        if not isinstance(raw, dict):
            continue
        tool = str(raw.get("tool") or "").strip().lower()
        if not tool or tool not in TOOLS:
            continue
        if tool in executed_lower:
            continue
        reason = str(raw.get("reason") or "").strip()
        params = _parse_step_params(str(raw.get("params") or ""), target)
        out.append(
            {
                "tool": tool,
                "parameters": params,
                "expected_outcome": reason or f"Follow-up using {tool}",
                "success_probability": 0.8,
                "execution_time_estimate": 60,
                "dependencies": [],
            }
        )
    return out


def plan_followup_from_context(
    *,
    target: str,
    objective: str = "comprehensive",
    summary: str = "",
    risk_level: str = "UNKNOWN",
    tools_executed: Optional[List[str]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
    chat_context: str = "",
    operator_note: str = "",
    llm_client: Any = None,
) -> Dict[str, Any]:
    """Plan follow-up workflow steps from Vrika session context."""
    tools_executed = list(tools_executed or [])
    findings = list(findings or [])

    if llm_client is None or not llm_client.is_available():
        return {
            "success": False,
            "error": "LLM is not available. Configure NYXSTRIKE_LLM_PROVIDER / NYXSTRIKE_LLM_MODEL.",
            "executive_summary": "",
            "workflow_steps": [],
            "attack_phases": [],
            "planner_source": "heuristic_empty",
        }

    findings_block = _format_findings(findings)
    context_snip = (chat_context or "").strip()
    if len(context_snip) > 20000:
        context_snip = context_snip[-20000:]

    user_message = (
        f"Target: {target}\n"
        f"Objective: {objective or 'comprehensive security assessment'}\n"
        f"Risk level: {risk_level or 'UNKNOWN'}\n"
        f"Tools already run: {', '.join(tools_executed) or 'N/A'}\n\n"
        f"Executive summary:\n{summary or '(none)'}\n\n"
        f"Discovered findings:\n{findings_block}\n\n"
    )
    if operator_note.strip():
        user_message += f"Operator note: {operator_note.strip()}\n\n"
    if context_snip:
        user_message += f"Chat and tool output context:\n{context_snip}\n\n"
    user_message += "Based on the above, produce a prioritised follow-up action plan."

    messages = [
        {"role": "system", "content": _FOLLOWUP_SYSTEM_PROMPT},
        {"role": "user", "content": user_message},
    ]

    try:
        response = llm_client.chat(messages, think=True, num_ctx=llm_client.num_ctx_analyse)
        if not isinstance(response, str):
            response = str(response or "")
    except Exception as exc:
        logger.warning("plan_followup_from_context: LLM failed: %s", exc)
        return {
            "success": False,
            "error": f"LLM call failed: {exc}",
            "executive_summary": "",
            "workflow_steps": [],
            "attack_phases": [],
            "planner_source": "heuristic_empty",
        }

    exec_summary, parsed_steps, _ = _parse_followup(response)
    workflow_steps = _parsed_to_workflow_steps(
        parsed_steps,
        target=target,
        tools_executed=tools_executed,
    )

    if not workflow_steps:
        return {
            "success": True,
            "executive_summary": exec_summary or "No additional high-value follow-up tools identified.",
            "workflow_steps": [],
            "attack_phases": [],
            "planner_source": "llm",
            "message": "LLM returned no new executable follow-up steps.",
        }

    step_dicts = [{"tool": s["tool"]} for s in workflow_steps]
    phases = _heuristic_phases(step_dicts)
    # Label follow-up phases distinctly
    for ph in phases:
        ph["label"] = f"Follow-up: {ph.get('label', ph.get('phase', 'Steps'))}"

    if not exec_summary:
        exec_summary = (
            f"Follow-up plan with {len(workflow_steps)} tools based on findings for {target}."
        )

    return {
        "success": True,
        "executive_summary": exec_summary,
        "workflow_steps": workflow_steps,
        "attack_phases": phases,
        "planner_source": "llm",
    }
