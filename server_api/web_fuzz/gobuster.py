from flask import Blueprint, request, jsonify
import logging
import shlex

from server_core.command_executor import execute_command
from server_core.singletons import COMMON_DIRB_PATH
from server_core.tool_paths import resolve_cli_tool, resolve_wordlist_path

logger = logging.getLogger(__name__)

api_web_fuzz_gobuster_bp = Blueprint("api_web_fuzz_gobuster", __name__)


@api_web_fuzz_gobuster_bp.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster with enhanced logging and intelligent error handling"""
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        raw_wl = params.get("wordlist")
        wordlist = resolve_wordlist_path(
            raw_wl if isinstance(raw_wl, str) else None,
            catalog_paths=(COMMON_DIRB_PATH,),
        )
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("Gobuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"Invalid gobuster mode: {mode}")
            return jsonify({
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }), 400

        gobuster_bin = resolve_cli_tool("gobuster")
        if not gobuster_bin:
            return jsonify(
                {
                    "error": "gobuster binary not found on PATH — install gobuster and ensure it is on PATH.",
                }
            ), 400

        command = (
            f"{shlex.quote(gobuster_bin)} {mode} -u {shlex.quote(str(url).strip())} "
            f"-w {shlex.quote(wordlist)}"
        )

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"Starting Gobuster {mode} scan: {url}")

        result = execute_command(command)

        logger.info(f"Gobuster scan completed for {url}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
