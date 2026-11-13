"""Publish as external_smoke.py beside connector.py; no credential files or writes.

Only workflow_dispatch on a standard GitHub-hosted Linux runner is accepted.
Runner metadata is GitHub's attestation, not independent network geolocation.
A PASS proves read-only public MCP access from that runner, not every network.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import sys

from connector import upstream
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DISCOVERY_URL = "https://jordan-workbench.github.io/agent-board-access/endpoint.json"
EXPECTED_TOOLS = {
    "list_boards",
    "create_board",
    "delete_board",
    "list_stacks",
    "list_cards",
    "get_card",
    "create_card",
    "update_card",
    "move_card",
    "add_comment",
    "list_comments",
}


def credentials_from_env(env):
    required = {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
    }
    if any(env.get(key) != value for key, value in required.items()):
        raise ValueError("Require GitHub-hosted Linux workflow_dispatch")
    token = env.get("MCP_SMOKE_TOKEN", "")
    pin = env.get("MCP_VERIFY_KEY", "")
    if not re.fullmatch(r"[A-Za-z0-9._~+/=-]{32,512}", token):
        raise ValueError("Missing or invalid smoke credential")
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pin, validate=True))
    except (ValueError, TypeError):
        raise ValueError("Missing or invalid public verification pin") from None
    return {"bearer_token": token, "verification_key": pin, "discovery_url": DISCOVERY_URL}


def rows(result):
    if result.isError:
        raise ValueError("Read failed")
    if result.structuredContent is not None:
        value = result.structuredContent
        value = value.get("result", value)
    else:
        value = [json.loads(item.text) for item in result.content if item.type == "text"]
        if len(value) == 1 and isinstance(value[0], list):
            value = value[0]
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError("Unexpected list response")
    return value


async def check_session(session):
    result = await session.list_tools()
    if result.nextCursor or len(result.tools) != 11 or {tool.name for tool in result.tools} != EXPECTED_TOOLS:
        raise ValueError("Unexpected capabilities")
    boards = rows(await session.call_tool("list_boards", {}))
    ids = [board.get("id") for board in boards]
    if (any(type(i) is not int or i < 2 for i in ids)
            or len(set(ids)) != len(ids) or 2 not in ids):
        raise ValueError("Unexpected board scope")
    if any(board["id"] != 2 and (
        not isinstance(board.get("project_key"), str) or not board["project_key"].strip()
    ) for board in boards):
        raise ValueError("Unmarked board scope")
    stacks = rows(await session.call_tool("list_stacks", {"board_id": 2}))
    ids = [stack.get("id") for stack in stacks]
    if len(stacks) != 5 or any(type(i) is not int or i < 1 for i in ids) or len(set(ids)) != 5:
        raise ValueError("Unexpected stack count")
    # Only read tools, even if a server regression incorrectly accepts invalid input.
    denials = [
        ("list_stacks", {"board_id": 1}),
        ("list_stacks", {"board_id": "2"}),
        ("list_stacks", {}),
        ("list_stacks", {"board_id": True}),
        ("list_cards", {"board_id": 1, "stack_id": 1}),
    ]
    for name, arguments in denials:
        # A network/protocol failure is NOT evidence of a scope/schema denial.
        result = await session.call_tool(name, arguments)
        if not result.isError:
            raise ValueError("Expected denial was accepted")
    return {
        "status": "PASS",
        "tools": 11,
        "boards": len(boards),
        "stacks": 5,
        "denials": len(denials),
        "runner_environment": "github-hosted",
    }


async def main():
    credentials = credentials_from_env(os.environ)
    async with asyncio.timeout(210):
        # Connector upstream fetches discovery WITHOUT auth, verifies its signature,
        # freshness and HTTPS scope, THEN opens the bearer client and initializes
        # the real MCP SDK session. Credentials stay in memory; no file is created.
        async with upstream(credentials) as session:
            report = await check_session(session)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    # SDK/http errors may contain remote bodies. Never emit their text or tracebacks.
    logging.disable(logging.CRITICAL)
    try:
        if len(sys.argv) != 1:
            raise ValueError("Arguments are not accepted")
        asyncio.run(main())
    except Exception:
        print("FAIL", file=sys.stderr)
        sys.exit(1)
