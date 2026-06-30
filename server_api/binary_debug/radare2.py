from flask import Blueprint, request, jsonify
import logging
import os

from server_core.command_executor import execute_command

logger = logging.getLogger(__name__)

api_binary_debug_radare2_bp = Blueprint("api_binary_debug_radare2", __name__)


import uuid

@api_binary_debug_radare2_bp.route("/api/tools/radare2", methods=["POST"])
def radare2():
    """Execute Radare2 for binary analysis and reverse engineering with enhanced logging"""
    try:
        params = request.json
        binary = params.get("binary", "")
        commands = params.get("commands", "")
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 Radare2 called without binary parameter")
            return jsonify({
                "error": "Binary parameter is required"
            }), 400

        temp_script = ""
        if commands:
            # Use unique filename to avoid race conditions and ensure it exists when r2 is called
            temp_script = f"/tmp/r2_commands_{uuid.uuid4().hex[:8]}.txt"
            
            # r2 scripts should have commands separated by newlines, not just semicolons if passed via file
            formatted_commands = commands.replace(";", "\n")
            with open(temp_script, "w") as f:
                f.write(formatted_commands + "\n")
            
            # Using -i runs the script before the prompt, -c runs a command. 
            # We want to run the script and then quit, so we append the quit command.
            command = f"r2 -q -i {temp_script} "
            if additional_args:
                command += f"{additional_args} "
            command += f"{binary}"
        else:
            command = f"r2 -q "
            if additional_args:
                command += f"{additional_args} "
            command += f"{binary}"

        logger.info(f"🔧 Starting Radare2 analysis: {binary}")
        result = execute_command(command)

        if temp_script and os.path.exists(temp_script):
            try:
                os.remove(temp_script)
            except OSError:
                pass

        logger.info(f"📊 Radare2 analysis completed for {binary}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in radare2 endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
