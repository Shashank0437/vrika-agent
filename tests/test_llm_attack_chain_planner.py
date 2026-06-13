"""Tests for hybrid LLM attack-chain planner candidate filtering and parsing."""

from shared.target_profile import TargetProfile
from shared.target_types import TargetType

from server_core.intelligence.llm_attack_chain_planner import (
    filter_candidates_by_operator_note,
    _heuristic_phases,
    _parse_paths,
    _parse_phases,
    plan_hybrid_attack_chain,
)


def _web_profile() -> TargetProfile:
    p = TargetProfile(target="https://example.com")
    p.target_type = TargetType.WEB_APPLICATION
    p.confidence_score = 0.9
    p.risk_level = "medium"
    return p


class TestFilterCandidatesByOperatorNote:
    def test_api_only_narrows_candidates(self):
        candidates = ["nmap", "subfinder", "theharvester", "nuclei", "sqlmap", "gau"]
        api_only = filter_candidates_by_operator_note(candidates, "API only focus on REST endpoints")
        assert "subfinder" not in api_only
        assert "theharvester" not in api_only
        assert "gau" not in api_only
        assert any(t in api_only for t in ("nuclei", "sqlmap", "arjun"))

    def test_no_brute_excludes_brute_tools(self):
        candidates = ["nmap", "gobuster", "nuclei", "hydra", "nikto"]
        filtered = filter_candidates_by_operator_note(candidates, "no brute force on this target")
        assert "hydra" not in filtered
        assert "gobuster" not in filtered
        assert "nmap" in filtered


class TestParsingHelpers:
    def test_parse_paths(self):
        text = (
            "SUMMARY: test\n"
            "PATH: web surface → SQLi → data access\n"
            "PATH: misconfig → cred leak\n"
        )
        paths = _parse_paths(text)
        assert len(paths) == 2
        assert "SQLi" in paths[0]

    def test_parse_phases(self):
        text = "PHASE: RECON | Reconnaissance | 1, 2\nPHASE: VULN | Vuln scan | 3"
        phases = _parse_phases(text, 4)
        assert len(phases) == 2
        assert phases[0]["phase"] == "RECON"
        assert phases[0]["step_indices"] == [0, 1]
        assert phases[1]["step_indices"] == [2]


class TestHeuristicFallback:
    def test_plan_without_llm_uses_heuristic(self):
        from server_core.singletons import decision_engine

        result = plan_hybrid_attack_chain(
            decision_engine=decision_engine,
            profile=_web_profile(),
            objective="comprehensive",
            operator_note="",
            target="https://example.com",
            llm_client=None,
        )
        assert result["success"]
        assert result["planner_source"] == "heuristic"
        assert result["attack_chain"].steps
        assert result["executive_summary"]
        assert result["attack_phases"]

    def test_heuristic_phases_from_steps(self):
        steps = [
            {"tool": "nmap"},
            {"tool": "nuclei"},
            {"tool": "subfinder"},
        ]
        phases = _heuristic_phases(steps)
        assert phases
        keys = {p["phase"] for p in phases}
        assert "RECON" in keys or "VULN" in keys or "OSINT" in keys
