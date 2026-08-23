"""
server_core/adk/__init__.py

Google Agent Development Kit (ADK) Integration for Vrika.
"""

from server_core.adk.state import VrikaAgentState, TargetKnowledgeState, DiscoveredFinding, extract_state_from_tool_output
from server_core.adk.prompts import build_consolidated_system_prompt
from server_core.adk.tools import normalize_tool_parameters
from server_core.adk.agents import VrikaOrchestrator, SPECIALIST_REGISTRY
from server_core.adk.telemetry import get_langfuse, trace_turn, TraceContext

__all__ = [
    "VrikaAgentState",
    "TargetKnowledgeState",
    "DiscoveredFinding",
    "extract_state_from_tool_output",
    "build_consolidated_system_prompt",
    "normalize_tool_parameters",
    "VrikaOrchestrator",
    "SPECIALIST_REGISTRY",
    "get_langfuse",
    "trace_turn",
    "TraceContext",
]
