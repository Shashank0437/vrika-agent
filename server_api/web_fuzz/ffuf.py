from flask import Blueprint, request, jsonify
import logging
import shlex

from server_core.command_executor import execute_command
from server_core.singletons import COMMON_DIRB_PATH
from server_core.tool_paths import resolve_cli_tool, resolve_wordlist_path

logger = logging.getLogger(__name__)

api_web_fuzz_ffuf_bp = Blueprint("api_web_fuzz_ffuf", __name__)


@api_web_fuzz_ffuf_bp.route("/api/tools/ffuf", methods=["POST"])
def ffuf():
    """Execute FFuf web fuzzer with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        raw_wl = params.get("wordlist")
        wordlist = resolve_wordlist_path(
            raw_wl if isinstance(raw_wl, str) else None,
            catalog_paths=(COMMON_DIRB_PATH,),
        )
        mode = params.get("mode", "directory")
        match_codes = params.get("match_codes", "200,204,301,302,307,401,403")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 FFuf called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        ffuf_bin = resolve_cli_tool("ffuf")
        if not ffuf_bin:
            return jsonify(
                {
                    "error": "ffuf binary not found on PATH — install ffuf and ensure it is on PATH.",
                }
            ), 400

        uq = shlex.quote(str(url).strip())
        wq = shlex.quote(wordlist)
        fq = shlex.quote(ffuf_bin)

        command = fq

        if mode == "directory":
            command += f" -u {uq}/FUZZ -w {wq}"
        elif mode == "vhost":
            command += f" -u {uq} -H {shlex.quote('Host: FUZZ')} -w {wq}"
        elif mode == "parameter":
            command += f" -u {uq}?FUZZ=value -w {wq}"
        else:
            command += f" -u {uq} -w {wq}"

        command += f" -mc {match_codes}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting FFuf {mode} fuzzing: {url}")
        result = execute_command(command)
        logger.info(f"📊 FFuf fuzzing completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in ffuf endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
