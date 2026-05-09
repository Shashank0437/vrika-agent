# mcp_tools/web_fuzz/dirsearch.py

from typing import Dict, Any
import asyncio

def register_dirsearch_tools(mcp, api_client, logger):
    @mcp.tool()
    async def dirsearch_scan(url: str, extensions: str = "php,html,js,txt,xml,json",
                      wordlist: str = "",
                      threads: int = 30, recursive: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Dirsearch for advanced directory and file discovery with enhanced logging.

        Args:
            url: The target URL
            extensions: File extensions to search for
            wordlist: Optional path; omit or empty to use bundled / catalog fallback when Kali lists are absent
            threads: Number of threads to use
            recursive: Enable recursive scanning
            additional_args: Additional Dirsearch arguments

        Returns:
            Advanced directory discovery results
        """
        data = {
            "url": url,
            "extensions": extensions,
            "threads": threads,
            "recursive": recursive,
            "additional_args": additional_args,
        }
        if isinstance(wordlist, str) and wordlist.strip():
            data["wordlist"] = wordlist.strip()
        logger.info(f"📁 Starting Dirsearch scan: {url}")
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None, lambda: api_client.safe_post("api/tools/dirsearch", data)
        )
        if result.get("success"):
            logger.info(f"✅ Dirsearch scan completed for {url}")
        else:
            logger.error(f"❌ Dirsearch scan failed for {url}")
        return result