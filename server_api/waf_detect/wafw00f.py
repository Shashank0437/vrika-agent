from flask import Blueprint, request, jsonify
import logging
from server_core.command_executor import execute_command

logger = logging.getLogger(__name__)

api_waf_detect_wafw00f_bp = Blueprint("api_waf_detect_wafw00f", __name__)


@api_waf_detect_wafw00f_bp.route("/api/tools/wafw00f", methods=["POST"])
def wafw00f():
    """Execute wafw00f to identify and fingerprint WAF products with enhanced logging"""
    try:
        params = request.json or {}
        raw = params.get("target") or params.get("url") or ""
        target = str(raw).strip()
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🛡️ Wafw00f called without target/url parameter")
            return jsonify({
                "error": "Target or url parameter is required"
            }), 400

        if not target.lower().startswith(("http://", "https://")):
            target = "https://" + target

        command = f"wafw00f {target}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🛡️ Starting Wafw00f WAF detection: {target}")
        result = execute_command(command)
        logger.info(f"📊 Wafw00f completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in wafw00f endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
