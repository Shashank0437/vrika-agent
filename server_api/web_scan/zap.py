from flask import Blueprint, request, jsonify
import logging
from server_core.command_executor import execute_command
from server_api.web_scan.burpsuite import burpsuite_alternative
from server_core.tool_run_context import current_stream_run_id

logger = logging.getLogger(__name__)

api_web_scan_zap_bp = Blueprint("api_web_scan_zap", __name__)


@api_web_scan_zap_bp.route("/api/tools/zap", methods=["POST"])
def zap():
    """Execute OWASP ZAP with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "baseline")
        api_key = params.get("api_key", "")
        daemon = params.get("daemon", False)
        port = params.get("port", "8090")
        host = params.get("host", "0.0.0.0")
        format_type = params.get("format", "xml")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not target and scan_type != "daemon":
            logger.warning("🎯 ZAP called without target parameter")
            return jsonify({
                "error": "Target parameter is required for scans"
            }), 400

        if daemon:
            command = f"zaproxy -daemon -host {host} -port {port}"
            if api_key:
                command += f" -config api.key={api_key}"
        else:
            command = f"zaproxy -cmd -quickurl {target}"

            if format_type:
                command += f" -quickout {format_type}"

            if output_file:
                command += f" -quickprogress -dir \"{output_file}\""

            if api_key:
                command += f" -config api.key={api_key}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting ZAP scan: {target}")
        result = execute_command(command)
        logger.info(f"📊 ZAP scan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in zap endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@api_web_scan_zap_bp.route("/api/tools/zaproxy-alternative", methods=["POST"])
def zaproxy_alternative():
    """Execute OWASP ZAP Alternative (simulated web scanner)"""
    logger.info(f"🔄 Routing ZAP Alternative to Burp Alternative logic")
    # For now, reuse the same comprehensive scanner logic since both are web vulnerability scanners
    return burpsuite_alternative()
