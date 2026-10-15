import asyncio
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from crawlcheck import CrawlCheck
from crawlcheck.mcp import McpPreflight, with_preflight, McpPreflightRefused
async def go(url, **o):
    cc = CrawlCheck(); pf = McpPreflight(cc, **o)
    try:
        await pf.before_connect(url)
    except McpPreflightRefused as e:
        print(url, "REFUSED", e.stage, "-", e.why, "| decision", e.receipt and e.receipt.get("decision")); return
    async with streamable_http_client(url) as (r, w):
        async with with_preflight(ClientSession(r, w), cc, server_url=url, preflight=pf) as s:
            await s.initialize(); t = await s.list_tools(); print(url, "CONNECTED", len(t.tools), "tools; receipt", pf.receipt["decision"], pf.receipt["sha256"][:16])
asyncio.run(go("https://mcp.example.com/mcp"))
asyncio.run(go("https://crawlcheck.io/mcp"))
asyncio.run(go("https://crawlcheck.io/mcp", confirm=lambda rc: True))
