from flask import Blueprint, request, jsonify
import logging
from server_core.command_executor import execute_command

logger = logging.getLogger(__name__)

api_osint_recon_ng_bp = Blueprint("api_osint_recon_ng", __name__)

@api_osint_recon_ng_bp.route("/api/tools/osint/recon_ng", methods=["POST"])
def recon_ng():
    """Execute Recon-ng"""
    try:
        params = request.json
        workspace = params.get("workspace", "default")
        module = params.get("module", "")
        additional_args = params.get("additional_args", "")

        command = f"recon-ng -w {workspace} {additional_args}"
        if module:
            command = f"recon-ng -w {workspace} -m {module} {additional_args}"
            
        logger.info(f"🚀 Executing Recon-ng: {command}")
        result = execute_command(command)
        return jsonify({"success": True, "output": result})
    except Exception as e:
        logger.error(f"❌ Recon-ng execution failed: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500
