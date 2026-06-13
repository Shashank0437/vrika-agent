"""REST API for workflow skills (same content as MCP skill resources, no MCP required)."""

import logging

from flask import Blueprint, jsonify

from server_core.skill_loader import get_skill_document, list_skill_summaries

logger = logging.getLogger(__name__)

api_skills_bp = Blueprint("api_skills", __name__)


@api_skills_bp.route("/api/skills", methods=["GET"])
def list_skills():
    try:
        skills = list_skill_summaries()
        return jsonify({"success": True, "skills": skills, "count": len(skills)})
    except Exception as exc:
        logger.exception("list_skills failed")
        return jsonify({"success": False, "error": str(exc)}), 500


@api_skills_bp.route("/api/skills/<skill_slug>", methods=["GET"])
def get_skill(skill_slug: str):
    try:
        doc = get_skill_document(skill_slug)
        if not doc:
            return jsonify({"success": False, "error": f"Skill not found: {skill_slug}"}), 404
        return jsonify({"success": True, **doc})
    except Exception as exc:
        logger.exception("get_skill failed for %r", skill_slug)
        return jsonify({"success": False, "error": str(exc)}), 500
