from typing import Dict, Any
import asyncio

def register_osint_theharvester_tool(mcp, api_client, logger):
    @mcp.tool()
    async def theharvester(domain: str, source: str = "all", limit: int = 500) -> Dict[str, Any]:
        """
        Execute theHarvester for passive information gathering.

        Args:
            domain: The target domain
            source: The data source to query (default: all)
            limit: Limit the number of search results (default: 500)

        Returns:
            theHarvester results
        """
        data = {
            "domain": domain,
            "source": source,
            "limit": limit
        }
        logger.info(f"🔍 Starting theHarvester: {domain}")
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None, lambda: api_client.safe_post("api/tools/osint/theharvester", data)
        )
        if result.get("success"):
            logger.info(f"✅ theHarvester completed for {domain}")
        else:
            logger.error(f"❌ theHarvester failed for {domain}")
        return result
