from flask import Blueprint, request, jsonify
import logging
import shlex

from server_core.command_executor import execute_command
from server_core.tool_paths import resolve_cli_tool

logger = logging.getLogger(__name__)

api_web_crawl_katana_bp = Blueprint("api_web_crawl_katana", __name__)


@api_web_crawl_katana_bp.route("/api/tools/katana", methods=["POST"])
def katana():
    """Execute Katana for next-generation crawling and spidering with enhanced logging"""
    try:
        params = request.json
        url = (params.get("url") or params.get("target") or "").strip()
        depth = params.get("depth", 3)
        js_crawl = params.get("js_crawl", True)
        form_extraction = params.get("form_extraction", True)
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Katana called without URL parameter")
            return jsonify({"error": "URL or target parameter is required"}), 400

        katana_bin = resolve_cli_tool("katana")
        if not katana_bin:
            return jsonify(
                {
                    "error": "katana binary not found on PATH or in ~/go/bin — install with "
                    "`go install github.com/projectdiscovery/katana/cmd/katana@latest` "
                    "(or `agent/scripts/install_recon_go_tools.sh`).",
                }
            ), 400

        command = f"{shlex.quote(katana_bin)} -u {shlex.quote(url)} -d {int(depth)}"

        if js_crawl:
            command += " -jc"

        if form_extraction:
            command += " -fx"

        if output_format == "json":
            command += " -jsonl"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"⚔️  Starting Katana crawl: {url}")
        result = execute_command(command)
        logger.info(f"📊 Katana crawl completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in katana endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
