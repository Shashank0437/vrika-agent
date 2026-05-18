from flask import Blueprint, request, jsonify
import logging
import shlex
from server_core.command_executor import execute_command

logger = logging.getLogger(__name__)

api_web_scan_sqlmap_bp = Blueprint("api_web_scan_sqlmap", __name__)


@api_web_scan_sqlmap_bp.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """Execute sqlmap with enhanced logging"""
    try:
        params = request.json or {}
        url = (params.get("url") or "").strip()
        data = (params.get("data") or "").strip()
        additional_args = (params.get("additional_args") or "").strip()

        if not url:
            logger.warning("🎯 SQLMap called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        # Quote the URL so query-string characters (&, ?, =, etc.) survive shell=True.
        # Without this, '&' becomes a backgrounding operator and the command breaks.
        command = f"sqlmap -u {shlex.quote(url)} --batch"

        if data:
            command += f" --data={shlex.quote(data)}"

        if additional_args:
            # additional_args is operator-supplied free text; keep as-is so flags like
            # --level=5 --risk=3 work, but caller is responsible for safety.
            command += f" {additional_args}"

        logger.info(f"💉 Starting SQLMap scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 SQLMap scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in sqlmap endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
