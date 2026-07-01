# mcp_tools/web_scan/zap.py

from typing import Dict, Any
import asyncio

def register_zap_tool(mcp, api_client, logger):
    @mcp.tool()
    async def zap_scan(target: str = "", scan_type: str = "baseline", api_key: str = "", daemon: bool = False, port: str = "8090", host: str = "0.0.0.0", format_type: str = "xml", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute OWASP ZAP with enhanced logging.

        Args:
            target: Target URL
            scan_type: Type of scan (baseline, full, api)
            api_key: ZAP API key
            daemon: Run in daemon mode
            port: Port for ZAP daemon
            host: Host for ZAP daemon
            format_type: Output format (xml, json, html)
            output_file: Output file path
            additional_args: Additional ZAP arguments

        Returns:
            ZAP scan results
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "api_key": api_key,
            "daemon": daemon,
            "port": port,
            "host": host,
            "format": format_type,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting ZAP scan: {target}")
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None, lambda: api_client.safe_post("api/tools/zap", data)
        )
        if result.get("success"):
            logger.info(f"✅ ZAP scan completed for {target}")
        else:
            logger.error(f"❌ ZAP scan failed for {target}")
        return result

    @mcp.tool()
    async def zaproxy_alternative_scan(target: str = "", scan_type: str = "baseline", api_key: str = "", port: str = "8090", output_format: str = "xml", additional_args: str = "") -> Dict[str, Any]:
        """
        Comprehensive OWASP ZAP alternative combining HTTP framework and browser agent for complete web security testing.

        Args:
            target: Target URL or domain to scan
            scan_type: Type of scan (baseline, full, api)
            api_key: ZAP API key
            port: Port for ZAP
            output_format: Output format
            additional_args: Additional arguments

        Returns:
            Comprehensive security assessment results
        """
        data_payload = {
            "target": target,
            "scan_type": scan_type,
            "api_key": api_key,
            "port": port,
            "output_format": output_format,
            "additional_args": additional_args
        }

        logger.info(f"🔥 Starting ZAP Alternative {scan_type} scan: {target}")
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None, lambda: api_client.safe_post("api/tools/zaproxy-alternative", data_payload)
        )

        if result.get("success"):
            logger.info(f"✅ ZAP Alternative scan completed for {target}")

            # Enhanced logging for comprehensive results
            if result.get("result", {}).get("summary"):
                summary = result["result"]["summary"]
                total_vulns = summary.get("total_vulnerabilities", 0)
                pages_analyzed = summary.get("pages_analyzed", 0)
                security_score = summary.get("security_score", 0)

                logger.info(f" SCAN SUMMARY ")
                logger.info(f"  📊 Pages Analyzed: {pages_analyzed}")
                logger.info(f"  🚨 Vulnerabilities: {total_vulns}")
                logger.info(f"  🛡️  Security Score: {security_score}/100")

                # Log vulnerability breakdown
                vuln_breakdown = summary.get("vulnerability_breakdown", {})
                for severity, count in vuln_breakdown.items():
                    if count > 0:
                        logger.info(f"  {severity.upper()}: {count}")
        else:
            logger.error(f"❌ ZAP Alternative scan failed for {target}")

        return result
