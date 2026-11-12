"""Portable stdio MCP -> signed-discovery -> authenticated HTTPS connector.

No VPN, provider login, browser automation, or stable tunnel hostname is needed.
The private credential file supplies a pinned discovery verification key. Never
retry a tool mutation automatically: a transport failure may have happened after
its commit. Only the scoped remote server's nine native tools are exposed.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import datetime as dt
import json
import os
import re
import stat
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from mcp.client.streamable_http import streamable_http_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from mcp import ClientSession

TOOLS = {
    "list_boards",
    "list_stacks",
    "list_cards",
    "get_card",
    "create_card",
    "update_card",
    "move_card",
    "add_comment",
    "list_comments",
}


def load_credentials(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd) as f:
            s = os.fstat(f.fileno())
            if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077:
                raise ValueError
            data = json.loads(f.read(65537))
        if set(data) != {"bearer_token", "discovery_url", "verification_key"}:
            raise ValueError
        if not isinstance(data["bearer_token"], str) or not re.fullmatch(
            r"[A-Za-z0-9._~+/=-]{32,512}", data["bearer_token"]
        ):
            raise ValueError
        u = urlsplit(data["discovery_url"])
        if (
            u.scheme != "https"
            or not u.hostname
            or u.username is not None
            or u.password is not None
            or u.query
            or u.fragment
            or u.port not in (None, 443)
        ):
            raise ValueError
        public = base64.b64decode(data["verification_key"], validate=True)
        Ed25519PublicKey.from_public_bytes(public)
        return data
    except (OSError, ValueError, TypeError, KeyError):
        raise ValueError(
            "Cannot load protected connector credentials; require valid owner-only regular file"
        ) from None


def verify_discovery(envelope, public_key, *, now=None):
    try:
        payload = envelope["payload"]
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            base64.b64decode(envelope["signature"], validate=True), raw
        )
        if type(payload["schema"]) is not int or payload["schema"] != 1:
            raise ValueError
        now = now or dt.datetime.now(dt.timezone.utc)
        issued = dt.datetime.fromisoformat(payload["issued_at"])
        expiry = dt.datetime.fromisoformat(payload["expires_at"])
        if (
            issued.tzinfo is None
            or expiry.tzinfo is None
            or expiry <= now
            or issued > now + dt.timedelta(minutes=5)
            or expiry - issued > dt.timedelta(days=2)
        ):
            raise ValueError
        u = urlsplit(payload["mcp_url"])
        if (
            u.scheme != "https"
            or u.username is not None
            or u.password is not None
            or u.port not in (None, 443)
            or u.path != "/mcp"
            or u.query
            or u.fragment
            or not re.fullmatch(r"[a-z0-9-]{1,63}\.trycloudflare\.com", u.hostname or "")
        ):
            raise ValueError
        if payload["board_url"] != "https://" + u.hostname + "/apps/deck/board/2":
            raise ValueError
        return payload["mcp_url"]
    except Exception:
        raise ValueError("Untrusted, expired, or out-of-scope signed endpoint discovery") from None


@asynccontextmanager
async def upstream(credentials):
    # Discovery is deliberately fetched WITHOUT Authorization or shared cookies.
    async with httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=30) as public:
        response = await public.get(credentials["discovery_url"], params={"fresh": os.urandom(8).hex()})
        response.raise_for_status()
        if len(response.content) > 65536:
            raise ValueError("Discovery response too large")
        url = verify_discovery(
            response.json(), base64.b64decode(credentials["verification_key"], validate=True)
        )
    async with httpx.AsyncClient(
        headers={"Authorization": "Bearer " + credentials["bearer_token"]},
        trust_env=False,
        follow_redirects=False,
        timeout=60,
    ) as client:
        async with streamable_http_client(url, http_client=client) as (reader, writer, _):
            async with ClientSession(
                reader, writer, read_timeout_seconds=dt.timedelta(seconds=60)
            ) as session:
                await session.initialize()
                yield session


class PortableRelay:
    """One owner task retains the upstream context and serializes tool requests."""

    def __init__(self, credentials):
        self.credentials = credentials
        self.queue = asyncio.Queue()

    async def request(self, name, arguments):
        future = asyncio.get_running_loop().create_future()
        await self.queue.put((name, arguments, future))
        async with asyncio.timeout(90):
            return await future

    async def run(self):
        while True:
            item = await self.queue.get()
            try:
                async with upstream(self.credentials) as session:
                    while True:
                        name, arguments, future = item
                        if not future.cancelled():
                            try:
                                result = (
                                    await session.list_tools()
                                    if name == "__list_tools__"
                                    else await session.call_tool(name, arguments)
                                )
                            except Exception:
                                if not future.done():
                                    future.set_exception(
                                        ValueError(
                                            "Remote operation failed; completion may be uncertain. Read back before retrying a write."
                                        )
                                    )
                                # Drop the failed connection. NEVER replay this request.
                                break
                            if not future.done():
                                future.set_result(result)
                        item = await self.queue.get()
            except asyncio.CancelledError:
                raise
            except Exception:
                future = item[2]
                if not future.done():
                    future.set_exception(ValueError("Remote connection or signed discovery unavailable"))


async def main(path):
    credentials = load_credentials(path)
    server = Server("agentdeck-portable")
    relay = PortableRelay(credentials)
    worker = asyncio.create_task(relay.run())

    @server.list_tools()
    async def list_tools():
        result = await relay.request("__list_tools__", {})
        if {tool.name for tool in result.tools} != TOOLS:
            raise ValueError("Unexpected remote capabilities; refusing discovery")
        return result.tools

    @server.call_tool(validate_input=False)
    async def call_tool(name, arguments):
        if name not in TOOLS:
            raise ValueError("Tool is not permitted")
        return await relay.request(name, arguments or {})

    try:
        async with stdio_server() as (reader, writer):
            await server.run(reader, writer, server.create_initialization_options())
    finally:
        worker.cancel()
        try:
            await worker
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(main(args.credentials))
