from flask import Blueprint, request, jsonify
import logging

from server_core.command_executor import execute_command

logger = logging.getLogger(__name__)

api_vuln_intel_vulnx_bp = Blueprint("api_vuln_intel_vulnx", __name__)

@api_vuln_intel_vulnx_bp.route("/api/vuln-intel/vulnx", methods=["POST"])
def vulnx():
    """VulnX CMS vulnerability scanner"""
    try:
        params = request.json or {}
        target = params.get("target", "") or params.get("url", "")
        
        if not target:
            return jsonify({
                "error": "The 'target' or 'url' parameter is required for vulnx."
            }), 400

        # Build command
        command = f"vulnx -u \"{target}\""
        
        if params.get("cms", False) or params.get("cms_info", False):
            command += " --cms"
        if params.get("exploit", False):
            command += " -e"
        if params.get("web_info", False):
            command += " -w"
        if params.get("dns", False):
            command += " --dns"

        logger.info(f"Starting vulnx analysis on target: {target}")

        result = execute_command(command)

        logger.info("vulnx analysis completed")
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in vulnx endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500