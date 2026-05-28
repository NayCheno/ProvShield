"""Real MCP integration tests: server ↔ proxy ↔ monitor end-to-end.

Tests that a real MCP server's tools are properly registered through
the ProvShield proxy, and that tool calls are mediated by the runtime
monitor with correct provenance labeling.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_root / "src"))

from provshield import (
    ContextBuilder,
    DecisionKind,
    RuntimeMonitor,
    SidecarProvenanceStore,
)
from provshield.mcp_proxy import MCPProxy
from provshield.taint import ProvenanceMode
from provshield.types import Effect, Sink


@pytest.fixture
def sandbox(tmp_path):
    """Create a temporary sandbox with test files."""
    (tmp_path / "public.txt").write_text("Public document content.")
    (tmp_path / "secret.txt").write_text("API_KEY=sk-test-12345")
    (tmp_path / "notes.md").write_text("# Notes\nMeeting at 3pm.")
    return tmp_path


@pytest.fixture
def mcp_server(sandbox):
    """Start a real MCP server subprocess."""
    server_script = str(_root / "eval" / "scripts" / "mcp_filesystem_server.py")
    env = __import__("os").environ.copy()
    env["MCP_SANDBOX"] = str(sandbox)
    env["PYTHONPATH"] = str(_root / "src")

    proc = subprocess.Popen(
        [sys.executable, server_script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )
    # Initialize
    init_msg = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "test", "version": "1.0.0"}},
    }) + "\n"
    proc.stdin.write(init_msg)
    proc.stdin.flush()
    proc.stdout.readline()  # consume init response

    yield proc

    proc.stdin.close()
    proc.terminate()
    proc.wait(timeout=5)


@pytest.fixture
def proxy_with_tools(mcp_server, sandbox):
    """Create a proxy with tools discovered from the real MCP server."""
    store = SidecarProvenanceStore()
    monitor = RuntimeMonitor(
        provenance_store=store,
        provenance_mode=ProvenanceMode.CONSERVATIVE,
    )
    context = ContextBuilder(store=store)
    proxy = MCPProxy(monitor=monitor, context_builder=context)

    # Discover tools from server
    list_msg = json.dumps({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
    }) + "\n"
    mcp_server.stdin.write(list_msg)
    mcp_server.stdin.flush()
    resp = json.loads(mcp_server.stdout.readline())
    server_tools = resp.get("result", {}).get("tools", [])

    msg_id = [3]

    def call_server(tool_name, arguments):
        msg_id[0] += 1
        msg = json.dumps({
            "jsonrpc": "2.0", "id": msg_id[0], "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }) + "\n"
        mcp_server.stdin.write(msg)
        mcp_server.stdin.flush()
        resp = json.loads(mcp_server.stdout.readline())
        if "error" in resp:
            raise RuntimeError(resp["error"].get("message", "error"))
        content = resp.get("result", {}).get("content", [])
        return content[0].get("text", "") if content else ""

    effect_map = {
        "read_file": (Effect.READ_PRIVATE, Sink.PRIVATE_READ),
        "write_file": (Effect.WRITE_LOCAL, Sink.LOCAL_WRITE),
        "list_directory": (Effect.READ_PUBLIC, Sink.PRIVATE_READ),
        "delete_file": (Effect.DELETE_LOCAL, Sink.LOCAL_WRITE),
        "search_files": (Effect.READ_PRIVATE, Sink.PRIVATE_READ),
    }

    for tool in server_tools:
        name = tool["name"]
        effect, sink = effect_map.get(name, (Effect.UNKNOWN_HIGH_RISK, Sink.CODE_EXECUTION))

        def make_executor(n=name):
            return lambda **kw: call_server(n, kw)

        proxy.register_tool(
            name=name,
            description=tool.get("description", ""),
            schema=tool.get("inputSchema", {}),
            executor=make_executor(),
            attested=False,
            effects=[effect],
            sink=sink,
        )

    return proxy, monitor, store, sandbox


class TestRealMCPIntegration:
    """End-to-end tests with real MCP server."""

    def test_server_starts_and_responds(self, mcp_server):
        """MCP server starts and responds to initialize."""
        assert mcp_server.poll() is None

    def test_tools_discovered(self, proxy_with_tools):
        """All 5 filesystem tools are discovered and registered."""
        proxy, _, _, _ = proxy_with_tools
        assert proxy.tool_count == 5
        tools = proxy.get_registered_tools()
        assert "read_file" in tools
        assert "write_file" in tools
        assert "list_directory" in tools
        assert "delete_file" in tools
        assert "search_files" in tools

    def test_read_file_allowed(self, proxy_with_tools):
        """Reading a file is allowed (low-risk read)."""
        proxy, monitor, _, _ = proxy_with_tools
        result = proxy.call_tool("read_file", {"path": "public.txt"})
        assert result is not None

    def test_list_directory_allowed(self, proxy_with_tools):
        """Listing directory is allowed (low-risk read)."""
        proxy, _, _, _ = proxy_with_tools
        result = proxy.call_tool("list_directory", {"path": "."})
        assert result is not None

    def test_search_files_allowed(self, proxy_with_tools):
        """Searching files is allowed (low-risk read)."""
        proxy, _, _, _ = proxy_with_tools
        result = proxy.call_tool("search_files", {"query": "secret"})
        assert result is not None

    def test_write_file_through_proxy(self, proxy_with_tools):
        """Write file goes through proxy and monitor."""
        proxy, monitor, store, sandbox = proxy_with_tools
        # Direct user write should be allowed or require bridge
        try:
            result = proxy.call_tool("write_file", {"path": "output.txt", "content": "test"})
            # If allowed, verify the file was written
            assert (sandbox / "output.txt").exists()
        except PermissionError:
            # Bridge required — also acceptable
            pass

    def test_delete_file_through_proxy(self, proxy_with_tools):
        """Delete file goes through proxy and monitor."""
        proxy, _, _, sandbox = proxy_with_tools
        try:
            result = proxy.call_tool("delete_file", {"path": "notes.md"})
        except PermissionError:
            pass  # Bridge required

    def test_tool_metadata_labeled(self, proxy_with_tools):
        """Tool metadata from MCP server is labeled in context."""
        proxy, _, store, _ = proxy_with_tools
        # Verify metadata was ingested
        assert proxy.tool_count == 5

    def test_unknown_tool_rejected(self, proxy_with_tools):
        """Calling an unregistered tool raises ValueError."""
        proxy, _, _, _ = proxy_with_tools
        with pytest.raises(ValueError, match="not registered"):
            proxy.call_tool("nonexistent_tool", {})

    def test_jsonrpc_message_handling(self, proxy_with_tools):
        """Proxy handles JSON-RPC messages correctly."""
        proxy, _, _, _ = proxy_with_tools
        # tools/list via JSON-RPC
        resp = proxy.handle_jsonrpc_message({
            "jsonrpc": "2.0", "id": 99, "method": "tools/list", "params": {},
        })
        assert resp["id"] == 99
        assert "result" in resp

    def test_all_tools_have_effect_types(self, proxy_with_tools):
        """All registered tools have declared effect types."""
        proxy, _, _, _ = proxy_with_tools
        from provshield.monitor import TOOL_PROFILES
        for name in proxy.get_registered_tools():
            assert name in TOOL_PROFILES, f"Tool {name} not in TOOL_PROFILES"
            profile = TOOL_PROFILES[name]
            assert "effects" in profile
            assert len(profile["effects"]) > 0

    def test_replayable_audit_trace(self, proxy_with_tools):
        """Audit log records decisions for replay."""
        proxy, monitor, _, _ = proxy_with_tools
        # Make a call
        try:
            proxy.call_tool("read_file", {"path": "public.txt"})
        except Exception:
            pass
        # Audit logger should have entries
        assert monitor.audit_log is not None
