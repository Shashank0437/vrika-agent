from flask import Blueprint, request, jsonify
import logging
import shlex

from server_core.command_executor import execute_command
from server_core.tool_paths import resolve_cli_tool, scope_to_domain

logger = logging.getLogger(__name__)

api_url_recon_waybackurls_bp = Blueprint("api_url_recon_waybackurls", __name__)


@api_url_recon_waybackurls_bp.route("/api/tools/waybackurls", methods=["POST"])
def waybackurls():
    """Execute Waybackurls for historical URL discovery with enhanced logging"""
    try:
        params = request.json
        raw = params.get("domain") or params.get("target") or ""
        domain = scope_to_domain(str(raw))
        get_versions = params.get("get_versions", False)
        no_subs = params.get("no_subs", False)
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 Waybackurls called without domain parameter")
            return jsonify(
                {"error": "domain or target parameter is required (hostname or http(s) URL)"}
            ), 400

        wb_bin = resolve_cli_tool("waybackurls")
        if not wb_bin:
            return jsonify(
                {
                    "error": "waybackurls binary not found on PATH or in ~/go/bin — install with "
                    "`go install github.com/tomnomnom/waybackurls@latest` "
                    "(or `agent/scripts/install_recon_go_tools.sh`).",
                }
            ), 400

        command = f"{shlex.quote(wb_bin)} {shlex.quote(domain)}"

        if get_versions:
            command += " --get-versions"

        if no_subs:
            command += " --no-subs"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🕰️  Starting Waybackurls discovery: {domain}")
        result = execute_command(command)
        logger.info(f"📊 Waybackurls discovery completed for {domain}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in waybackurls endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
