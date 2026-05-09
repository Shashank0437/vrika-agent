from flask import Blueprint, request, jsonify
import logging
import shlex

from server_core.command_executor import execute_command
from server_core.singletons import COMMON_DIRB_PATH
from server_core.tool_paths import resolve_cli_tool, resolve_wordlist_path

logger = logging.getLogger(__name__)

api_web_fuzz_dirb_bp = Blueprint("api_web_fuzz_dirb", __name__)


@api_web_fuzz_dirb_bp.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Execute dirb with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        raw_wl = params.get("wordlist")
        wordlist = resolve_wordlist_path(
            raw_wl if isinstance(raw_wl, str) else None,
            catalog_paths=(COMMON_DIRB_PATH,),
        )
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Dirb called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        dirb_bin = resolve_cli_tool("dirb")
        if not dirb_bin:
            return jsonify(
                {
                    "error": "dirb binary not found on PATH — install dirb (e.g. apt install dirb) "
                    "and ensure it is on PATH.",
                }
            ), 400

        command = (
            f"{shlex.quote(dirb_bin)} {shlex.quote(str(url).strip())} {shlex.quote(wordlist)}"
        )

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"📁 Starting Dirb scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Dirb scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in dirb endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
