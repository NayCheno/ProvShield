"""MCP stdio transport: reads JSON-RPC messages from stdin, processes through
ProvShield monitor, writes responses to stdout.

This implements the MCP stdio transport specification:
- Reads newline-delimited JSON-RPC 2.0 messages from stdin
- Processes through MCPProxy (which mediates via RuntimeMonitor)
- Writes JSON-RPC 2.0 responses to stdout

Usage:
    python -m provshield.mcp_transport

Or programmatically:
    transport = MCPStdioTransport(proxy)
    transport.run()  # blocks until stdin closes
"""

from __future__ import annotations

import json
import sys
from typing import Any, TextIO

from .mcp_proxy import MCPProxy


class MCPStdioTransport:
    """MCP stdio transport: JSON-RPC over stdin/stdout.

    Responsibilities:
      - Read newline-delimited JSON-RPC messages from input stream
      - Route through MCPProxy for provenance-aware mediation
      - Write JSON-RPC responses to output stream
      - Handle errors gracefully
    """

    def __init__(
        self,
        proxy: MCPProxy,
        input_stream: TextIO | None = None,
        output_stream: TextIO | None = None,
    ) -> None:
        self.proxy = proxy
        self.input = input_stream or sys.stdin
        self.output = output_stream or sys.stdout
        self._running = False

    def run(self) -> None:
        """Main loop: read messages from stdin, process, write to stdout."""
        self._running = True
        while self._running:
            try:
                line = self.input.readline()
                if not line:
                    # EOF
                    break
                line = line.strip()
                if not line:
                    continue

                message = json.loads(line)
                response = self.proxy.handle_jsonrpc_message(message)
                self._write_response(response)

            except json.JSONDecodeError as e:
                self._write_error(None, -32700, f"Parse error: {e}")
            except Exception as e:
                self._write_error(None, -32603, f"Internal error: {e}")

    def stop(self) -> None:
        """Stop the transport loop."""
        self._running = False

    def _write_response(self, response: dict[str, Any]) -> None:
        """Write a JSON-RPC response to stdout."""
        text = json.dumps(response, default=str)
        self.output.write(text + "\n")
        self.output.flush()

    def _write_error(self, msg_id: Any, code: int, message: str) -> None:
        """Write a JSON-RPC error response."""
        response = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": code, "message": message},
        }
        self._write_response(response)


class MCPHttpTransport:
    """MCP HTTP/SSE transport stub.

    This is a placeholder for HTTP-based MCP transport.
    A full implementation would use aiohttp or similar to serve
    JSON-RPC over HTTP with Server-Sent Events for streaming.
    """

    def __init__(self, proxy: MCPProxy, host: str = "127.0.0.1", port: int = 8080) -> None:
        self.proxy = proxy
        self.host = host
        self.port = port

    def handle_request(self, body: str) -> str:
        """Handle a single HTTP request containing a JSON-RPC message.

        Args:
            body: JSON-RPC message as string.

        Returns:
            JSON-RPC response as string.
        """
        try:
            message = json.loads(body)
            response = self.proxy.handle_jsonrpc_message(message)
            return json.dumps(response, default=str)
        except json.JSONDecodeError as e:
            return json.dumps({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {e}"},
            })
