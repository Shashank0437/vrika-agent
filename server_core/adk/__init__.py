"""
server_core/adk/__init__.py

Google Agent Development Kit (ADK) Integration for Vrika.
"""

from server_core.adk.state import VrikaAgentState, TargetKnowledgeState, DiscoveredFinding, extract_state_from_tool_output
from server_core.adk.prompts import build_consolidated_system_prompt
from server_core.adk.tools import get_adk_tools_for_names, get_adk_tool_declaration, normalize_tool_parameters
from server_core.adk.agents import VrikaOrchestrator, SPECIALIST_REGISTRY
from server_core.adk.summarizer import compact_dialogue_turns
from server_core.adk.runner import stream_adk_agent_turn

__all__ = [
    "VrikaAgentState",
    "TargetKnowledgeState",
    "DiscoveredFinding",
    "extract_state_from_tool_output",
    "build_consolidated_system_prompt",
    "get_adk_tools_for_names",
    "get_adk_tool_declaration",
    "normalize_tool_parameters",
    "VrikaOrchestrator",
    "SPECIALIST_REGISTRY",
    "compact_dialogue_turns",
    "stream_adk_agent_turn",
]
