"""
Hybrid LLM attack-chain planner: decision-engine candidates + LLM phased plan.

Falls back to heuristic create_attack_chain() when the LLM is unavailable or parsing fails.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from shared.attack_chain import AttackChain
from shared.attack_step import AttackStep
from shared.target_profile import TargetProfile
from tool_registry import TOOLS

from server_core.intelligence.tool_catalog import objective_alias
from server_core.llm_agent import _parse_followup

logger = logging.getLogger(__name__)

_PATH_RE = re.compile(r"^PATH:\s*(?P<text>.+)$", re.IGNORECASE | re.MULTILINE)
_PHASE_RE = re.compile(
    r"PHASE:\s*(?P<key>[^|]+)\s*\|\s*(?P<label>[^|]+)\s*\|\s*(?P<indices>[^\n]+)",
    re.IGNORECASE,
)
_STEP_FULL_RE = re.compile(
    r"STEP:\s*(?P<tool>[^|\n]+)\s*\|\s*PARAMS:\s*(?P<params>[^|]+)\s*\|\s*REASON:\s*(?P<reason>[^\n]+)",
    re.IGNORECASE,
)
_STEP_NO_PARAMS_RE = re.compile(
    r"STEP:\s*(?P<tool>[^|\n]+)\s*\|\s*REASON:\s*(?P<reason>[^\n]+)",
    re.IGNORECASE,
)
_STEP_TOOL_ONLY_RE = re.compile(r"^\s*STEP:\s*(?P<tool>[^\n|]+)\s*$", re.IGNORECASE | re.MULTILINE)

_API_FOCUS_KEYWORDS = frozenset(
    {"api", "rest", "graphql", "swagger", "openapi", "endpoint", "json"}
)
_API_TOOLS = frozenset(
    {
        "arjun",
        "nuclei",
        "sqlmap",
        "dalfox",
        "nikto",
        "wpscan",
        "ffuf",
        "gobuster",
        "whatweb",
        "http-headers",
        "nmap",
    }
)
_OSINT_TOOLS = frozenset(
    {"subfinder", "theharvester", "gau", "waybackurls", "amass", "whois", "dig"}
)
_BRUTE_TOOLS = frozenset(
    {
        "hydra",
        "gobuster",
        "ffuf",
        "john",
        "hashcat",
        "medusa",
        "patator",
    }
)
_WEB_TOOLS = frozenset(
    {
        "nikto",
        "nuclei",
        "sqlmap",
        "dalfox",
        "gobuster",
        "ffuf",
        "whatweb",
        "wpscan",
        "arjun",
        "http-headers",
    }
)

_CATEGORY_PHASE: Dict[str, str] = {
    "network_recon": "RECON",
    "web_recon": "RECON",
    "dns": "RECON",
    "osint": "OSINT",
    "enumeration": "ENUM",
    "web_vuln": "VULN",
    "vulnerability": "VULN",
    "exploitation": "EXPLOIT",
    "password": "EXPLOIT",
}

_PHASE_LABELS = {
    "RECON": "Reconnaissance",
    "OSINT": "OSINT",
    "ENUM": "Enumeration",
    "VULN": "Vulnerability scan",
    "EXPLOIT": "Exploitation",
    "OTHER": "Follow-up",
}

_ATTACK_CHAIN_SYSTEM_PROMPT = """\
You are NyxStrike, an expert penetration testing planner.

Given a target profile, precision objective, operator constraints, and an ALLOWED tool list,
produce a phased attack chain plan. Output ONLY structured tags — no markdown prose.

Required format (emit each applicable line):
  SUMMARY: <one paragraph executive summary of approach and current assumptions>
  PATH: <likely attack path as a short phrase, e.g. "web surface → SQLi → data access">
  PHASE: <KEY> | <Human label> | <comma-separated 1-based step numbers in this phase>
  STEP: <tool_name> | PARAMS: <key=val,key2=val2> | REASON: <one sentence rationale>

Rules:
  - Emit SUMMARY exactly once.
  - Emit 2–3 PATH: lines describing distinct plausible attack paths.
  - Emit 2–5 PHASE: lines grouping steps (keys like RECON, ENUM, VULN, OSINT, EXPLOIT).
  - Emit 4–12 STEP: lines ordered by execution priority.
  - Each STEP line format: STEP: <tool_name> | PARAMS: <key=val,...> | REASON: <one sentence>
    (PARAMS may be empty or target=<session target> if no extra parameters are needed.)
  - STEP tool_name must be an exact lowercase identifier from ALLOWED_TOOLS only.
  - Respect operator constraints in the user message — do not plan excluded techniques.
  - Do NOT call tools; planning only.
"""


def _normalize_tool_name(raw: str) -> str:
    text = (raw or "").strip().lower()
    text = text.strip("`\"' ")
    text = re.sub(r"\s*\(.*\)$", "", text).strip()
    return text


def _strip_code_fences(text: str) -> str:
    return re.sub(r"```[\w]*\n?", "", text or "")


def _parse_attack_chain_steps(transcript: str) -> List[Dict[str, Any]]:
    """Parse STEP lines from planner output; tolerates missing PARAMS and minor formatting."""
    text = _strip_code_fences(transcript)
    steps: List[Dict[str, Any]] = []
    seen_tools: Set[str] = set()

    def _append(tool_raw: str, params: str = "", reason: str = "") -> None:
        tool = _normalize_tool_name(tool_raw)
        if not tool or tool in seen_tools:
            return
        seen_tools.add(tool)
        steps.append(
            {
                "tool": tool,
                "params": (params or "").strip(),
                "reason": (reason or "").strip(),
            }
        )

    for pattern in (_STEP_FULL_RE, _STEP_NO_PARAMS_RE):
        for m in pattern.finditer(text):
            _append(m.group("tool"), m.groupdict().get("params") or "", m.groupdict().get("reason") or "")

    if steps:
        return steps

    for m in _STEP_TOOL_ONLY_RE.finditer(text):
        _append(m.group("tool"))

    if steps:
        return steps

    # Legacy parser used by follow-up flows
    _, legacy_steps, _ = _parse_followup(text)
    for raw in legacy_steps:
        if isinstance(raw, dict):
            _append(str(raw.get("tool") or ""), str(raw.get("params") or ""), str(raw.get("reason") or ""))
    return steps


def _call_planner_llm(llm_client: Any, messages: List[Dict[str, str]]) -> str:
    """Return planner transcript, merging reasoning/thinking when the model omits visible content."""
    backend = getattr(llm_client, "_backend", None)
    if backend is not None:
        try:
            raw = backend.chat(messages, think=True, num_ctx=llm_client.num_ctx_analyse)
        except TypeError:
            raw = backend.chat(messages, think=True, num_ctx=llm_client.num_ctx_analyse)
        if isinstance(raw, dict):
            content = str(raw.get("content") or "").strip()
            thinking = str(raw.get("thinking_content") or "").strip()
            has_steps = lambda t: bool(re.search(r"STEP:\s*", t, re.IGNORECASE))
            if content and has_steps(content):
                return content
            if thinking and has_steps(thinking):
                return thinking if not content else f"{content}\n{thinking}".strip()
            if thinking and len(content) < 120:
                return f"{thinking}\n{content}".strip()
            return content or thinking
        return str(raw or "")

    return str(llm_client.chat(messages, think=True, num_ctx=llm_client.num_ctx_analyse) or "")


def _parse_summary(transcript: str) -> str:
    summary_match = re.search(
        r"SUMMARY:\s*(.+?)(?=^\s*(?:PATH:|PHASE:|STEP:)\s*|\Z)",
        transcript,
        re.I | re.S | re.M,
    )
    if not summary_match:
        return ""
    return summary_match.group(1).strip()


def _parse_step_params(raw: str, target: str) -> Dict[str, Any]:
    params: Dict[str, Any] = {}
    text = (raw or "").strip()
    if text.startswith("{") and text.endswith("}"):
        try:
            loaded = json.loads(text)
            if isinstance(loaded, dict):
                return loaded
        except (ValueError, TypeError):
            pass
    for part in text.split(","):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, val = part.split("=", 1)
        params[key.strip()] = val.strip()
    if not params and target:
        params["target"] = target
    return params


def _parse_paths(transcript: str) -> List[str]:
    paths: List[str] = []
    for m in _PATH_RE.finditer(transcript):
        text = m.group("text").strip()
        if text and text not in paths:
            paths.append(text)
    return paths[:3]


def _parse_phases(transcript: str, step_count: int) -> List[Dict[str, Any]]:
    phases: List[Dict[str, Any]] = []
    for m in _PHASE_RE.finditer(transcript):
        key = m.group("key").strip().upper().replace(" ", "_")
        label = m.group("label").strip()
        raw_indices = m.group("indices").strip()
        indices: List[int] = []
        for piece in re.split(r"[,;\s]+", raw_indices):
            piece = piece.strip()
            if not piece:
                continue
            if piece.isdigit():
                idx = int(piece) - 1
                if 0 <= idx < step_count:
                    indices.append(idx)
        if indices:
            phases.append(
                {
                    "phase": key,
                    "label": label or _PHASE_LABELS.get(key, key),
                    "step_indices": indices,
                }
            )
    return phases


def _heuristic_phases(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    buckets: Dict[str, List[int]] = {}
    for i, step in enumerate(steps):
        tool = str(step.get("tool") or "").strip().lower()
        meta = TOOLS.get(tool) if tool else None
        category = str((meta or {}).get("category") or "").strip().lower()
        phase_key = _CATEGORY_PHASE.get(category, "OTHER")
        buckets.setdefault(phase_key, []).append(i)

    phases: List[Dict[str, Any]] = []
    for key in ("RECON", "OSINT", "ENUM", "VULN", "EXPLOIT", "OTHER"):
        indices = buckets.get(key)
        if indices:
            phases.append(
                {
                    "phase": key,
                    "label": _PHASE_LABELS.get(key, key),
                    "step_indices": indices,
                }
            )
    return phases


def filter_candidates_by_operator_note(
    candidates: List[str],
    operator_note: str,
    *,
    registry: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Boost or exclude tools based on operator custom prompt keywords."""
    note = (operator_note or "").strip().lower()
    if not note:
        return list(candidates)

    tools = registry or TOOLS
    pool = [t for t in candidates if t in tools]
    if not pool:
        pool = list(candidates)

    excluded: Set[str] = set()
    if any(k in note for k in ("no brute", "no brute force", "without brute", "no password crack")):
        excluded.update(_BRUTE_TOOLS)
    if "no osint" in note or "no passive" in note:
        excluded.update(_OSINT_TOOLS)
    if any(k in note for k in ("no scan", "no active", "passive only")):
        excluded.update({"nmap", "masscan", "rustscan", "nikto", "nuclei"})

    filtered = [t for t in pool if t not in excluded]

    focus_api = "api only" in note or "api focus" in note or "rest api" in note
    focus_osint = "osint only" in note or "passive only" in note or "osint focus" in note
    focus_web = "web only" in note or "web app" in note or "web application" in note

    if focus_api:
        filtered = [t for t in filtered if t in _API_TOOLS] or [t for t in pool if t in _API_TOOLS]
    elif focus_osint:
        filtered = [t for t in filtered if t in _OSINT_TOOLS] or [t for t in pool if t in _OSINT_TOOLS]
    elif focus_web:
        filtered = [t for t in filtered if t in _WEB_TOOLS] or [t for t in pool if t in _WEB_TOOLS]

    if not filtered:
        filtered = pool

    scored: List[Tuple[int, str]] = []
    for tool in filtered:
        score = 0
        if focus_api and tool in _API_TOOLS:
            score += 3
        if focus_osint and tool in _OSINT_TOOLS:
            score += 3
        if focus_web and tool in _WEB_TOOLS:
            score += 2
        for kw in _API_FOCUS_KEYWORDS:
            if kw in note and kw in tool:
                score += 2
        if tool in note:
            score += 4
        scored.append((score, tool))

    scored.sort(key=lambda x: (-x[0], x[1]))
    return [t for _, t in scored]


def _build_steps_from_llm(
    parsed_steps: List[Dict[str, Any]],
    *,
    profile: TargetProfile,
    objective: str,
    target: str,
    allowed: Set[str],
    decision_engine: Any,
) -> List[AttackStep]:
    out: List[AttackStep] = []
    objective_key = objective_alias(objective)

    for raw in parsed_steps:
        tool = str(raw.get("tool") or "").strip().lower()
        if not tool or tool not in TOOLS:
            continue
        if allowed and tool not in allowed:
            logger.debug("LLM planner tool %s outside candidate pool; accepting registered tool", tool)

        reason = str(raw.get("reason") or "").strip()
        params = _parse_step_params(str(raw.get("params") or ""), target)

        merged_context: Dict[str, Any] = {
            "objective": objective,
            "target_type": profile.target_type.value,
            "risk_level": profile.risk_level,
            "optimization_profile": "stealth" if objective_key == "stealth" else "normal",
        }
        merged_context.update(params)

        try:
            optimizer_params = decision_engine.optimize_parameters(tool, profile, merged_context)
        except Exception:
            optimizer_params = {}

        final_params = dict(optimizer_params)
        final_params.update(params)

        effectiveness = decision_engine._effective_score(
            tool,
            profile.target_type.value,
            decision_engine._build_context_key(profile, objective_key),
        )
        success_prob = max(0.01, min(0.99, effectiveness * profile.confidence_score))

        from server_core.intelligence.intelligent_decision_engine import TIME_ESTIMATES

        exec_time = TIME_ESTIMATES.get(tool, 180)

        out.append(
            AttackStep(
                tool=tool,
                parameters=final_params,
                expected_outcome=reason or f"Run {tool} against {target}",
                success_probability=success_prob,
                execution_time_estimate=exec_time,
            )
        )
    return out


def plan_hybrid_attack_chain(
    *,
    decision_engine: Any,
    profile: TargetProfile,
    objective: str,
    operator_note: str,
    target: str,
    llm_client: Any = None,
    runtime_context: Optional[Dict[str, Any]] = None,
    planner_mode: Optional[str] = None,
) -> Dict[str, Any]:
    """Plan attack chain via LLM over decision-engine candidates, with heuristic fallback."""
    runtime_context = runtime_context if isinstance(runtime_context, dict) else {}
    ranked = decision_engine.select_optimal_tools(profile, objective, planner_mode=planner_mode)
    candidates = filter_candidates_by_operator_note(ranked, operator_note)
    allowed = set(candidates)

    if llm_client is None or not llm_client.is_available():
        return _heuristic_plan(
            decision_engine,
            profile,
            objective,
            runtime_context=runtime_context,
            planner_mode=planner_mode,
        )

    profile_dict = profile.to_dict()
    techs = profile_dict.get("technologies") or []
    tech_str = ", ".join(str(t) for t in techs[:8]) if techs else "unknown"

    user_message = (
        f"Target: {target}\n"
        f"Target type: {profile.target_type.value}\n"
        f"Technologies: {tech_str}\n"
        f"Risk level: {profile.risk_level}\n"
        f"Precision objective: {objective}\n"
        f"Operator constraints: {operator_note.strip() or '(none)'}\n\n"
        f"ALLOWED_TOOLS: {', '.join(candidates)}\n\n"
        "Produce the phased attack chain plan."
    )

    messages = [
        {"role": "system", "content": _ATTACK_CHAIN_SYSTEM_PROMPT},
        {"role": "user", "content": user_message},
    ]

    try:
        response = _call_planner_llm(llm_client, messages)
    except Exception as exc:
        logger.warning("LLM attack chain planner failed: %s", exc)
        return _heuristic_plan(
            decision_engine,
            profile,
            objective,
            runtime_context=runtime_context,
            planner_mode=planner_mode,
        )

    parsed_steps = _parse_attack_chain_steps(response)
    summary = _parse_summary(response)
    attack_paths = _parse_paths(response)
    built_steps = _build_steps_from_llm(
        parsed_steps,
        profile=profile,
        objective=objective,
        target=target,
        allowed=allowed,
        decision_engine=decision_engine,
    )

    if len(built_steps) < 2:
        logger.warning(
            "LLM planner produced insufficient steps (parsed=%d built=%d); falling back to heuristic",
            len(parsed_steps),
            len(built_steps),
        )
        return _heuristic_plan(
            decision_engine,
            profile,
            objective,
            runtime_context=runtime_context,
            planner_mode=planner_mode,
        )

    chain = AttackChain(profile)
    for step in built_steps:
        chain.add_step(step)
    chain.calculate_success_probability()
    chain.risk_level = profile.risk_level

    step_dicts = chain.to_dict().get("steps") or []
    phases = _parse_phases(response, len(step_dicts))
    if not phases:
        phases = _heuristic_phases(step_dicts)

    if not summary:
        summary = (
            f"Phased {objective} assessment of {target} using {len(step_dicts)} tools "
            f"selected from intelligence profiling ({profile.target_type.value})."
        )
    if not attack_paths:
        attack_paths = [
            f"{profile.target_type.value} surface mapping → vulnerability validation → impact proof"
        ]

    return {
        "success": True,
        "attack_chain": chain,
        "executive_summary": summary,
        "attack_paths": attack_paths,
        "attack_phases": phases,
        "planner_source": "llm_hybrid",
    }


def _heuristic_plan(
    decision_engine: Any,
    profile: TargetProfile,
    objective: str,
    *,
    runtime_context: Optional[Dict[str, Any]] = None,
    planner_mode: Optional[str] = None,
) -> Dict[str, Any]:
    chain = decision_engine.create_attack_chain(
        profile,
        objective,
        runtime_context=runtime_context,
        planner_mode=planner_mode,
    )
    step_dicts = chain.to_dict().get("steps") or []
    phases = _heuristic_phases(step_dicts if isinstance(step_dicts, list) else [])
    summary = (
        f"Heuristic {objective} chain for {profile.target} "
        f"({profile.target_type.value}) with {len(step_dicts)} tools ranked by the decision engine."
    )
    paths = [
        f"Profile-driven {profile.target_type.value} assessment → tool-ranked enumeration → validation"
    ]
    return {
        "success": True,
        "attack_chain": chain,
        "executive_summary": summary,
        "attack_paths": paths,
        "attack_phases": phases,
        "planner_source": "heuristic",
    }
