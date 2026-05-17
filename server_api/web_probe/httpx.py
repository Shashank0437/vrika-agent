import logging
import os
import shlex

from flask import Blueprint, jsonify, request

from server_core.command_executor import execute_command
from server_core.tool_paths import resolve_cli_tool_go_paths_first

logger = logging.getLogger(__name__)

api_web_probe_httpx_bp = Blueprint("api_web_probe_httpx", __name__)


@api_web_probe_httpx_bp.route("/api/tools/httpx", methods=["POST"])
def httpx():
    """Execute ProjectDiscovery httpx (not the PyPI ``httpx`` CLI that shadows the same name on PATH)."""
    try:
        params = request.json or {}
        target = (params.get("target") or params.get("url") or "").strip()
        probe = params.get("probe", True)
        tech_detect = params.get("tech_detect", True)
        status_code = params.get("status_code", True)
        content_length = params.get("content_length", True)
        title = params.get("title", True)
        web_server = params.get("web_server", True)
        threads = params.get("threads", 50)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🌐 httpx called without target parameter")
            return jsonify({"error": "Target or url parameter is required"}), 400

        env_bin = (os.environ.get("NYXSTRIKE_HTTPX_BIN") or "").strip()
        httpx_bin = env_bin if env_bin else resolve_cli_tool_go_paths_first("httpx")
        if not httpx_bin:
            return jsonify(
                {
                    "error": "ProjectDiscovery httpx not found — install with "
                    "`go install github.com/projectdiscovery/httpx/cmd/httpx@latest` "
                    "so it lives in ~/go/bin, or set NYXSTRIKE_HTTPX_BIN to the full path. "
                    "PyPI `httpx` uses the same command name and breaks `-u` when it appears first on PATH.",
                }
            ), 400

        tq = shlex.quote(target)
        bq = shlex.quote(httpx_bin)
        command = f"{bq} -u {tq} -t {int(threads)}"

        if probe:
            command += " -probe"

        if tech_detect:
            command += " -tech-detect"

        if status_code:
            command += " -sc"

        if content_length:
            command += " -cl"

        if title:
            command += " -title"

        if web_server:
            command += " -server"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🌍 Starting httpx probe: {target}")
        result = execute_command(command)
        logger.info(f"📊 httpx probe completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in httpx endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
