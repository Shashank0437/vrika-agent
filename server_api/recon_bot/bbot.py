from flask import Blueprint, request, jsonify
from server_core.command_executor import execute_command
import logging

logger = logging.getLogger(__name__)

api_recon_bot_bbot_bp = Blueprint("api_recon_bot_bbot", __name__)


@api_recon_bot_bbot_bp.route("/api/bot/bbot", methods=["POST"])
def bbot_endpoint():
    """Endpoint for BBot interactions

    parameters:
        -f Enable these flags (e.g. -f subdomain-enum)
        -rf Require modules to have this flag (e.g. -rf safe)
        -ef Exclude these flags (e.g. -ef slow)
        -em Exclude these individual modules (e.g. -em ipneighbor)
    """
    try:
        data = request.get_json()
        if not data or "target" not in data:
            return jsonify({"error": "Missing 'target' in payload"}), 400
        target = data["target"]
        parameters = data.get("parameters", {})

        if isinstance(parameters, str):
            parameters = parameters.strip()
            if not parameters:
                parameters = {}
            else:
                import json
                try:
                    parameters = json.loads(parameters)
                except json.JSONDecodeError:
                    try:
                        import yaml
                        parameters = yaml.safe_load(parameters)
                    except Exception:
                        return jsonify({"error": "Failed to parse 'parameters' as JSON or YAML"}), 400

        if not isinstance(parameters, dict):
            return jsonify({"error": "The 'parameters' payload must be a dictionary or a valid JSON/YAML object mapping options to values."}), 400

        cmd_parts = ['bbot', "-t " + target]
        for key, value in parameters.items():
            if isinstance(value, str) and value:
                cmd_parts.append(f"-{key} {value}")

        result = execute_command(" ".join(cmd_parts), use_cache=False)

        logger.info(f"BBot scan completed for {target}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in BBot endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
