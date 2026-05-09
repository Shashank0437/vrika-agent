from flask import Blueprint, request, jsonify
import logging
import shlex

from server_core.command_executor import execute_command
from server_core.singletons import COMMON_DIRB_PATH, COMMON_DIRSEARCH_PATH
from server_core.tool_paths import resolve_cli_tool, resolve_wordlist_path

logger = logging.getLogger(__name__)

api_web_fuzz_dirsearch_bp = Blueprint("api_web_fuzz_dirsearch", __name__)


def _coerce_target_url(val: object) -> str:
    if val is None:
        return ""
    v = str(val).strip()
    if not v:
        return ""
    if v.startswith(("http://", "https://")):
        return v
    return f"https://{v}"


@api_web_fuzz_dirsearch_bp.route("/api/tools/dirsearch", methods=["POST"])
def dirsearch():
    """Execute Dirsearch for advanced directory and file discovery with enhanced logging"""
    try:
        params = request.json or {}
        raw_url = params.get("url") or params.get("target") or ""
        url = _coerce_target_url(raw_url)
        extensions = params.get("extensions", "php,html,js,txt,xml,json")
        raw_wl = params.get("wordlist")
        wordlist = resolve_wordlist_path(
            raw_wl if isinstance(raw_wl, str) else None,
            catalog_paths=(COMMON_DIRSEARCH_PATH, COMMON_DIRB_PATH),
        )
        threads = params.get("threads", 30)
        recursive = params.get("recursive", False)
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Dirsearch called without URL parameter")
            return jsonify({"error": "URL or target parameter is required"}), 400

        ds_bin = resolve_cli_tool("dirsearch")
        if not ds_bin:
            return jsonify(
                {
                    "error": "dirsearch binary not found on PATH or in ~/go/bin — install dirsearch "
                    "(e.g. `pip install dirsearch` or distro package) and ensure it is on PATH.",
                }
            ), 400

        command = (
            f"{shlex.quote(ds_bin)} -u {shlex.quote(url)} "
            f"-e {shlex.quote(str(extensions))} -w {shlex.quote(wordlist)} -t {int(threads)}"
        )

        if recursive:
            command += " -r"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"📁 Starting Dirsearch scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Dirsearch scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in dirsearch endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
