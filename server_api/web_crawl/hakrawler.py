from flask import Blueprint, request, jsonify
import logging
import shlex

from server_core.command_executor import execute_command
from server_core.tool_paths import resolve_cli_tool

logger = logging.getLogger(__name__)

api_web_crawl_hakrawler_bp = Blueprint("api_web_crawl_hakrawler", __name__)


@api_web_crawl_hakrawler_bp.route("/api/tools/hakrawler", methods=["POST"])
def hakrawler():
    """
    Execute Hakrawler for web endpoint discovery with enhanced logging

    Note: This implementation uses the standard Kali Linux hakrawler (hakluke/hakrawler)
    command line arguments, NOT the Elsfa7-110 fork. The standard version uses:
    - printf URL | hakrawler (stdin input)
    - -d for depth (not -depth)
    - -s for showing sources (not -forms)
    - -u for unique URLs
    - -subs for subdomain inclusion
    """
    try:
        params = request.json
        url = (params.get("url") or params.get("target") or "").strip()
        depth = params.get("depth", 2)
        forms = params.get("forms", True)
        robots = params.get("robots", True)
        sitemap = params.get("sitemap", True)
        wayback = params.get("wayback", False)
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🕷️ Hakrawler called without URL parameter")
            return jsonify({
                "error": "URL or target parameter is required"
            }), 400

        hakrawler_bin = resolve_cli_tool("hakrawler")
        if not hakrawler_bin:
            return jsonify(
                {
                    "error": "hakrawler binary not found on PATH or in ~/go/bin — install with "
                    "`go install github.com/hakluke/hakrawler/v2@latest` (or use "
                    "`agent/scripts/install_recon_go_tools.sh`) and ensure GOPATH/bin is on PATH.",
                }
            ), 400

        # Build command for standard hakrawler (stdin URL; printf avoids echo flag quirks)
        uq = shlex.quote(url)
        bq = shlex.quote(hakrawler_bin)
        command = f"printf '%s\\n' {uq} | {bq} -d {int(depth)}"

        if forms:
            command += " -s"  # Show sources (includes forms)
        if robots or sitemap or wayback:
            command += " -subs"  # Include subdomains for better coverage

        # Add unique URLs flag for cleaner output
        command += " -u"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🕷️ Starting Hakrawler crawling: {url}")
        result = execute_command(command)
        logger.info(f"📊 Hakrawler crawling completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in hakrawler endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
