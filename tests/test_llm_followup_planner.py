"""Tests for context-based follow-up planner."""

from server_core.intelligence.llm_followup_planner import (
    _parsed_to_workflow_steps,
    plan_followup_from_context,
)


class TestParsedToWorkflowSteps:
    def test_skips_already_executed_tools(self):
        parsed = [
            {"tool": "nmap", "params": "target=example.com", "reason": "again"},
            {"tool": "nuclei", "params": "target=example.com", "reason": "scan"},
        ]
        steps = _parsed_to_workflow_steps(
            parsed,
            target="example.com",
            tools_executed=["nmap"],
        )
        assert len(steps) == 1
        assert steps[0]["tool"] == "nuclei"

    def test_invalid_tool_excluded(self):
        parsed = [{"tool": "not_a_real_tool", "params": "", "reason": "x"}]
        steps = _parsed_to_workflow_steps(parsed, target="example.com", tools_executed=[])
        assert steps == []


class TestPlanFollowupNoLlm:
    def test_llm_unavailable_returns_error(self):
        result = plan_followup_from_context(
            target="example.com",
            llm_client=None,
        )
        assert result["success"] is False
        assert result["planner_source"] == "heuristic_empty"
        assert result["workflow_steps"] == []
