from flask import Blueprint, request, jsonify
import logging
import shlex

from server_core.command_executor import execute_command
from server_core.tool_paths import resolve_cli_tool, resolve_x8_wordlist

logger = logging.getLogger(__name__)

api_param_discovery_x8_bp = Blueprint("api_param_discovery_x8", __name__)


@api_param_discovery_x8_bp.route("/api/tools/x8", methods=["POST"])
def x8():
    """Execute x8 for hidden parameter discovery with enhanced logging"""
    try:
        params = request.json or {}
        url = (params.get("url") or "").strip()
        raw_wl = params.get("wordlist")
        method = params.get("method", "GET")
        body = params.get("body", "")
        headers = params.get("headers", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 x8 called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        wordlist = resolve_x8_wordlist(raw_wl if isinstance(raw_wl, str) else None)
        if not wordlist:
            return jsonify(
                {
                    "error": "No parameter wordlist found. Install SecLists, use the default "
                    "Kali x8 list, or pass wordlist with an existing file path.",
                    "success": False,
                }
            ), 400

        x8_bin = resolve_cli_tool("x8")
        if not x8_bin:
            return jsonify(
                {
                    "error": "x8 binary not found — install with `cargo install x8` or add "
                    "`~/.cargo/bin` to PATH.",
                    "success": False,
                }
            ), 400

        command = (
            f"{shlex.quote(x8_bin)} -u {shlex.quote(url)} -w {shlex.quote(wordlist)} "
            f"-X {shlex.quote(str(method))}"
        )

        if body:
            command += f" -b {shlex.quote(str(body))}"

        if headers:
            command += f" -H {shlex.quote(str(headers))}"

        if additional_args:
            command += f" {additional_args}"

        logger.info("🔍 Starting x8 parameter discovery: %s", url)
        result = execute_command(command, tool="x8")
        logger.info("📊 x8 parameter discovery completed for %s", url)
        return jsonify(result)
    except Exception as e:
        logger.error("💥 Error in x8 endpoint: %s", e)
        return jsonify({"error": f"Server error: {str(e)}"}), 500
