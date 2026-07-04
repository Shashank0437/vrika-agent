from typing import Dict, Any
import asyncio

def register_osint_recon_ng_tool(mcp, api_client, logger):
    @mcp.tool()
    async def recon_ng(workspace: str, module: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute recon-ng for web reconnaissance.

        Args:
            workspace: The workspace name
            module: Optional specific module to run
            additional_args: Optional additional arguments for recon-ng

        Returns:
            recon-ng analysis results
        """
        data = {
            "workspace": workspace,
            "module": module,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting recon-ng: {workspace}")
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None, lambda: api_client.safe_post("api/tools/osint/recon_ng", data)
        )
        if result.get("success"):
            logger.info(f"✅ recon-ng completed for {workspace}")
        else:
            logger.error(f"❌ recon-ng failed for {workspace}")
        return result
