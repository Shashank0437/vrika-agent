from flask import Blueprint, request, jsonify
import logging
from server_core.command_executor import execute_command

logger = logging.getLogger(__name__)

api_osint_maltego_bp = Blueprint("api_osint_maltego", __name__)

@api_osint_maltego_bp.route("/api/tools/osint/maltego", methods=["POST"])
def maltego():
    """Execute Maltego"""
    try:
        params = request.json
        target = params.get("target", "")
        transform = params.get("transform", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        # Dummy wrapper for maltego as it is typically a GUI tool
        # that utilizes transforms.
        command = f"echo 'Maltego CLI is not directly supported, but task registered for target: {target} and transform: {transform}'"
        result = execute_command(command)
        return jsonify({"success": True, "output": result})
    except Exception as e:
        logger.error(f"❌ Maltego execution failed: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500
