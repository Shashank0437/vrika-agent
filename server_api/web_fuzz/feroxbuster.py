from flask import Blueprint, request, jsonify
import logging
import shlex

from server_core.command_executor import execute_command
from server_core.singletons import COMMON_DIRB_PATH
from server_core.tool_paths import resolve_cli_tool, resolve_wordlist_path

logger = logging.getLogger(__name__)

api_web_fuzz_feroxbuster_bp = Blueprint("api_web_fuzz_feroxbuster", __name__)


@api_web_fuzz_feroxbuster_bp.route("/api/tools/feroxbuster", methods=["POST"])
def feroxbuster():
    """Execute Feroxbuster for recursive content discovery with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        raw_wordlist = params.get("wordlist")
        wordlist = resolve_wordlist_path(
            raw_wordlist if isinstance(raw_wordlist, str) else None,
            catalog_paths=(COMMON_DIRB_PATH,),
        )
        threads = params.get("threads", 10)
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Feroxbuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        ferox_bin = resolve_cli_tool("feroxbuster")
        if not ferox_bin:
            return jsonify(
                {
                    "error": "feroxbuster binary not found on PATH — install from "
                    "https://github.com/epi052/feroxbuster and ensure the binary is on PATH.",
                }
            ), 400

        command = (
            f"{shlex.quote(ferox_bin)} -u {shlex.quote(str(url).strip())} "
            f"-w {shlex.quote(wordlist)} -t {threads}"
        )

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Feroxbuster scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Feroxbuster scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in feroxbuster endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
