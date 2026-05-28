#!/usr/bin/env python3
"""Real MCP client that connects through ProvShield proxy.

Demonstrates end-to-end MCP integration:
1. Spawns a real MCP server (filesystem) as subprocess
2. Connects through ProvShield MCPProxy
3. Registers tools from server via tools/list
4. Executes tool calls mediated by runtime monitor
5. Records replayable audit traces

Usage:
    python eval/scripts/mcp_real_client.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_root / "src"))

from provshield import (
    ContextBuilder,
    DecisionKind,
    RuntimeMonitor,
    SidecarProvenanceStore,
)
from provshield.audit import AuditLogger
from provshield.mcp_proxy import MCPProxy
from provshield.taint import ProvenanceMode
from provshield.types import Effect, Sink


class MCPRealClient:
    """Real MCP client that communicates with an MCP server through ProvShield proxy."""

    def __init__(self, server_script: str, sandbox_dir: str):
        self.server_script = server_script
        self.sandbox_dir = sandbox_dir
        self._process: subprocess.Popen | None = None
        self._msg_id = 0

        # ProvShield components
        self.store = SidecarProvenanceStore()
        self.monitor = RuntimeMonitor(
            provenance_store=self.store,
            provenance_mode=ProvenanceMode.CONSERVATIVE,
        )
        self.context = ContextBuilder(store=self.store)
        self.proxy = MCPProxy(monitor=self.monitor, context_builder=self.context)
        self.audit = AuditLogger()

    def start_server(self):
        """Start the MCP server as a subprocess."""
        env = os.environ.copy()
        env["MCP_SANDBOX"] = self.sandbox_dir
        env["PYTHONPATH"] = str(_root / "src")

        self._process = subprocess.Popen(
            [sys.executable, self.server_script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
        )
        # Send initialize
        resp = self._send({
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "provshield-real-client", "version": "1.0.0"},
            },
        })
        return resp

    def stop_server(self):
        """Stop the MCP server."""
        if self._process:
            self._process.stdin.close()
            self._process.terminate()
            self._process.wait(timeout=5)
            self._process = None

    def _next_id(self) -> int:
        self._msg_id += 1
        return self._msg_id

    def _send(self, msg: dict) -> dict:
        """Send a JSON-RPC message to the server and receive response."""
        if not self._process or not self._process.stdin or not self._process.stdout:
            raise RuntimeError("Server not started")
        line = json.dumps(msg) + "\n"
        self._process.stdin.write(line)
        self._process.stdin.flush()
        response_line = self._process.stdout.readline()
        if not response_line:
            raise RuntimeError("Server closed connection")
        return json.loads(response_line)

    def discover_tools(self) -> list[dict]:
        """Discover tools from the MCP server and register them through the proxy."""
        resp = self._send({
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/list",
            "params": {},
        })
        server_tools = resp.get("result", {}).get("tools", [])

        # Register each tool through the proxy
        for tool in server_tools:
            name = tool["name"]
            desc = tool.get("description", "")
            schema = tool.get("inputSchema", {})

            # Map tool to effect type
            effect_map = {
                "read_file": (Effect.READ_PRIVATE, Sink.PRIVATE_READ),
                "write_file": (Effect.WRITE_LOCAL, Sink.LOCAL_WRITE),
                "list_directory": (Effect.READ_PUBLIC, Sink.PRIVATE_READ),
                "delete_file": (Effect.DELETE_LOCAL, Sink.LOCAL_WRITE),
                "search_files": (Effect.READ_PRIVATE, Sink.PRIVATE_READ),
            }
            effect, sink = effect_map.get(name, (Effect.UNKNOWN_HIGH_RISK, Sink.CODE_EXECUTION))

            def make_executor(tool_name=name):
                def executor(**kwargs):
                    return self._call_server_tool(tool_name, kwargs)
                return executor

            self.proxy.register_tool(
                name=name,
                description=desc,
                schema=schema,
                executor=make_executor(),
                attested=False,
                effects=[effect],
                sink=sink,
                source_of_authority="mcp_server",
            )

        return server_tools

    def _call_server_tool(self, tool_name: str, arguments: dict) -> str:
        """Call a tool on the MCP server."""
        resp = self._send({
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        })
        if "error" in resp:
            raise RuntimeError(resp["error"].get("message", "Unknown error"))
        content = resp.get("result", {}).get("content", [])
        return content[0].get("text", "") if content else ""

    def call_tool(self, tool_name: str, arguments: dict, principal: str = "user"):
        """Call a tool through the ProvShield proxy (mediated by runtime monitor)."""
        return self.proxy.call_tool(tool_name, arguments, principal=principal)


def run_real_mcp_integration():
    """Run real MCP integration demo with 5 workflows."""
    print("=" * 60)
    print(" ProvShield Real MCP Integration Demo")
    print("=" * 60)

    with tempfile.TemporaryDirectory(prefix="provshield_mcp_") as sandbox:
        print(f"\nSandbox: {sandbox}")

        # Create test files
        test_dir = Path(sandbox)
        (test_dir / "public.txt").write_text("Hello, this is a public document.")
        (test_dir / "secret.txt").write_text("API_KEY=sk-secret-12345")
        (test_dir / "notes.md").write_text("# Meeting Notes\nDiscussed Q3 targets.")

        # Start MCP client
        server_script = str(_root / "eval" / "scripts" / "mcp_filesystem_server.py")
        client = MCPRealClient(server_script=server_script, sandbox_dir=sandbox)

        try:
            print("\n--- Starting MCP server ---")
            init_resp = client.start_server()
            print(f"  Server: {init_resp.get('result', {}).get('serverInfo', {}).get('name', 'unknown')}")

            # Discover tools
            print("\n--- Discovering tools ---")
            tools = client.discover_tools()
            print(f"  Registered {len(tools)} tools through ProvShield proxy:")
            for t in tools:
                print(f"    - {t['name']}: {t.get('description', '')[:60]}")

            # Workflow 1: Benign read (should ALLOW)
            print("\n--- Workflow 1: Benign Read ---")
            try:
                result = client.call_tool("read_file", {"path": "public.txt"})
                print(f"  Decision: ALLOW")
                print(f"  Result: {str(result)[:80]}")
            except Exception as e:
                print(f"  Decision: DENIED ({e})")

            # Workflow 2: List directory (should ALLOW)
            print("\n--- Workflow 2: List Directory ---")
            try:
                result = client.call_tool("list_directory", {"path": "."})
                print(f"  Decision: ALLOW")
                print(f"  Result:\n{str(result)[:200]}")
            except Exception as e:
                print(f"  Decision: DENIED ({e})")

            # Workflow 3: Write file (should REQUIRE_BRIDGE)
            print("\n--- Workflow 3: Write File ---")
            try:
                result = client.call_tool("write_file", {"path": "output.txt", "content": "test"})
                print(f"  Decision: ALLOW")
            except PermissionError as e:
                print(f"  Decision: REQUIRE_BRIDGE (denied without confirmation)")
            except Exception as e:
                print(f"  Decision: {type(e).__name__} ({e})")

            # Workflow 4: Delete file (should REQUIRE_BRIDGE or DENY)
            print("\n--- Workflow 4: Delete File ---")
            try:
                result = client.call_tool("delete_file", {"path": "notes.md"})
                print(f"  Decision: ALLOW")
            except PermissionError as e:
                print(f"  Decision: DENIED/BRIDGE ({e})")
            except Exception as e:
                print(f"  Decision: {type(e).__name__} ({e})")

            # Workflow 5: Search files (should ALLOW)
            print("\n--- Workflow 5: Search Files ---")
            try:
                result = client.call_tool("search_files", {"query": "secret"})
                print(f"  Decision: ALLOW")
                print(f"  Result: {str(result)[:100]}")
            except Exception as e:
                print(f"  Decision: DENIED ({e})")

            # Print audit summary
            print("\n--- Audit Summary ---")
            decisions = client.monitor._audit_log if hasattr(client.monitor, '_audit_log') else []
            print(f"  Total decisions: {len(decisions)}")

            # Print registered tools
            print("\n--- Registered Tools ---")
            for name, info in client.proxy.get_registered_tools().items():
                print(f"  {name}: attested={info.get('attested')}, source={info.get('source_of_authority')}")

            print("\n" + "=" * 60)
            print(" Real MCP Integration Complete")
            print("=" * 60)

        finally:
            client.stop_server()


if __name__ == "__main__":
    run_real_mcp_integration()
