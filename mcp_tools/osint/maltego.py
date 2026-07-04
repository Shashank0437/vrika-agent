from typing import Dict, Any
import asyncio

def register_osint_maltego_tool(mcp, api_client, logger):
    @mcp.tool()
    async def maltego(target: str, transform: str = "") -> Dict[str, Any]:
        """
        Execute Maltego for link analysis and data mining.

        Args:
            target: The target domain or IP for Maltego analysis
            transform: Optional specific transform to run

        Returns:
            Maltego analysis results
        """
        data = {
            "target": target,
            "transform": transform
        }
        logger.info(f"🔍 Starting Maltego: {target}")
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None, lambda: api_client.safe_post("api/tools/osint/maltego", data)
        )
        if result.get("success"):
            logger.info(f"✅ Maltego completed for {target}")
        else:
            logger.error(f"❌ Maltego failed for {target}")
        return result
