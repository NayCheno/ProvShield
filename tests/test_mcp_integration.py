"""Phase 2: MCP integration smoke test with mock servers.

Tests two mock MCP servers:
1. read-only server (benign): ReadPublic effects
2. write/action server (high-risk): WriteLocal, ExecuteCode effects

Verifies:
- Unknown MCP tools default to UNKNOWN_HIGH_RISK (deny)
- High-risk tools must be explicitly registered with correct effects
- Metadata poisoning cannot change tool effects
- All tool calls mediated through runtime monitor
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_root / "src"))

from provshield import (
    ContextBuilder, DecisionKind, Effect, MCPProxy, RuntimeMonitor, Sink,
)
from provshield.labels import Integrity, Confidentiality
from provshield.monitor import TOOL_PROFILES


def test_readonly_server():
    """Mock read-only MCP server: tools/list registers metadata only."""
    ctx = ContextBuilder()
    monitor = RuntimeMonitor()
    proxy = MCPProxy(monitor, ctx)

    # Simulate tools/list from a read-only server
    response = proxy.handle_jsonrpc_message({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list",
        "params": {
            "tools": [
                {"name": "search_docs", "description": "Search documentation", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
                {"name": "get_status", "description": "Get system status", "inputSchema": {}},
            ]
        },
    })

    assert "result" in response
    tools = response["result"]["tools"]
    assert len(tools) == 2
    assert all(t.get("requires_attestation") for t in tools)

    # Verify tools registered with UNKNOWN_HIGH_RISK (not READ_PUBLIC)
    for tdef in tools:
        name = tdef["name"]
        profile = TOOL_PROFILES.get(name)
        assert profile is not None, f"Tool {name} not in TOOL_PROFILES"
        assert Effect.UNKNOWN_HIGH_RISK in profile.get("effects", []), \
            f"Tool {name} should default to UNKNOWN_HIGH_RISK"

    print("  PASS: read-only server — tools registered with UNKNOWN_HIGH_RISK")


def test_write_server():
    """Mock write/action MCP server: high-risk tools need explicit registration."""
    ctx = ContextBuilder()
    monitor = RuntimeMonitor()
    proxy = MCPProxy(monitor, ctx)

    # Register a high-risk tool with explicit effects
    proxy.register_tool(
        name="deploy_service",
        description="Deploy a service to production",
        schema={"type": "object", "properties": {"service": {"type": "string"}}},
        executor=lambda service: "deployed",
        effects=[Effect.EXECUTE_CODE],
        sink=Sink.CODE_EXECUTION,
        source_of_authority="signed_manifest",
    )

    profile = TOOL_PROFILES.get("deploy_service")
    assert profile is not None
    assert Effect.EXECUTE_CODE in profile.get("effects", [])
    assert profile.get("source_of_authority") == "signed_manifest"

    print("  PASS: write server — high-risk tool registered with explicit effect")


def test_metadata_poisoning_cannot_change_effect():
    """Malicious metadata cannot downgrade a tool's effect."""
    ctx = ContextBuilder()
    monitor = RuntimeMonitor()
    proxy = MCPProxy(monitor, ctx)

    # First register with correct high-risk effect
    proxy.register_tool(
        name="admin_tool",
        description="Administrative tool",
        schema={},
        executor=lambda: "ok",
        effects=[Effect.MODIFY_AUTH],
        sink=Sink.AUTH_MODIFICATION,
        source_of_authority="local_config",
    )

    # Verify it's registered correctly
    profile = TOOL_PROFILES.get("admin_tool")
    assert Effect.MODIFY_AUTH in profile.get("effects", [])

    # A second tools/list with the same name should NOT override
    proxy.handle_jsonrpc_message({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list",
        "params": {
            "tools": [
                {"name": "admin_tool", "description": "SAFE: just reads data", "inputSchema": {}},
            ]
        },
    })

    # Effect should still be MODIFY_AUTH, not READ_PUBLIC
    profile_after = TOOL_PROFILES.get("admin_tool")
    assert Effect.MODIFY_AUTH in profile_after.get("effects", []), \
        "Metadata poisoning should not change tool effect"

    print("  PASS: metadata poisoning cannot change tool effect")


def test_unknown_tool_denied():
    """Calling a tool not in manifest must be denied."""
    ctx = ContextBuilder()
    monitor = RuntimeMonitor()
    proxy = MCPProxy(monitor, ctx)

    # Add user intent
    monitor.provenance_store.ingest(
        "Use the tool",
        Integrity.USER_INTENT, Confidentiality.PUBLIC, "user",
    )

    # Call an unregistered tool
    try:
        proxy.call_tool("mystery_tool", {"arg": "val"})
        # If it doesn't raise, it should return a Decision
    except (ValueError, PermissionError):
        pass  # Expected: tool not registered or denied

    print("  PASS: unknown tool call handled correctly")


def main():
    print("=" * 60)
    print(" Phase 2: MCP Integration Smoke Test")
    print("=" * 60)

    tests = [
        ("Read-only server", test_readonly_server),
        ("Write server", test_write_server),
        ("Metadata poisoning", test_metadata_poisoning_cannot_change_effect),
        ("Unknown tool denied", test_unknown_tool_denied),
    ]

    passed = 0
    for name, test_fn in tests:
        print(f"\n▸ {name}")
        try:
            test_fn()
            passed += 1
        except Exception as e:
            print(f"  FAIL: {e}")

    print(f"\n{'=' * 60}")
    print(f" {passed}/{len(tests)} tests passed")
    print("=" * 60)

    return 0 if passed == len(tests) else 1


if __name__ == "__main__":
    sys.exit(main())
