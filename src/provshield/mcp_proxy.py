"""MCP proxy: intercepts tool registration and mediates tool calls.

This module implements a proxy that sits between the MCP client and MCP servers,
intercepting all tool registration and tool call messages. It labels tool metadata
at registration time and mediates all tool calls through the runtime monitor.

Supports MCP JSON-RPC message format for tools/list and tools/call.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Callable, Optional

from .context import ContextBuilder
from .monitor import RuntimeMonitor
from .types import Effect, NormalizedToolCall, Sink


class MCPProxy:
    """Proxy between MCP client and MCP servers.

    Responsibilities:
      - Intercept tool registration and label metadata
      - Mediate all tool calls through the runtime monitor
      - Label tool outputs
      - Apply network and filesystem guardrails
      - Handle MCP JSON-RPC messages (tools/list, tools/call)
    """

    def __init__(
        self,
        monitor: RuntimeMonitor,
        context_builder: ContextBuilder,
    ) -> None:
        self.monitor = monitor
        self.context = context_builder
        self._registered_tools: dict[str, dict[str, Any]] = {}
        self._tool_executors: dict[str, Callable[..., Any]] = {}

    def register_tool(
        self,
        name: str,
        description: str,
        schema: dict[str, Any],
        executor: Callable[..., Any],
        attested: bool = False,
    ) -> None:
        """Register a tool through the proxy.

        Unattested metadata is labeled as low-integrity ToolMetadata.
        """
        self._registered_tools[name] = {
            "name": name,
            "description": description,
            "schema": schema,
            "attested": attested,
        }
        self._tool_executors[name] = executor

        # Label metadata in context
        self.context.ingest_tool_metadata(
            {"name": name, "description": description, "schema": schema},
            tool_name=name,
            attested=attested,
        )

    def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        principal: str = "user",
    ) -> Any:
        """Call a tool through the proxy (mediated by runtime monitor)."""
        proposed_call = {
            "tool_name": tool_name,
            "arguments": arguments,
            "principal": principal,
        }

        executor = self._tool_executors.get(tool_name)
        if executor is None:
            raise ValueError(f"Tool {tool_name} not registered")

        def execute(call: NormalizedToolCall) -> Any:
            return executor(**call.arguments)

        return self.monitor.check_and_execute(proposed_call, execute)

    def handle_jsonrpc_message(self, message: dict[str, Any]) -> dict[str, Any]:
        """Handle an MCP JSON-RPC message.

        Intercepts tools/list and tools/call messages. Other messages
        are passed through unchanged.

        Args:
            message: JSON-RPC message dict with 'method', 'params', 'id'.

        Returns:
            Response dict with 'result' or 'error'.
        """
        method = message.get("method", "")
        params = message.get("params", {})
        msg_id = message.get("id")

        if method == "tools/list":
            return self._handle_tools_list(params, msg_id)
        elif method == "tools/call":
            return self._handle_tools_call(params, msg_id)
        else:
            # Pass through unknown methods
            return {"jsonrpc": "2.0", "id": msg_id, "result": None}

    def _handle_tools_list(
        self, params: dict[str, Any], msg_id: Any
    ) -> dict[str, Any]:
        """Handle tools/list: register and label all tool metadata."""
        tools = params.get("tools", [])
        registered = []
        for tool_def in tools:
            name = tool_def.get("name", "unknown")
            desc = tool_def.get("description", "")
            schema = tool_def.get("inputSchema", {})
            # Register with proxy (labels metadata as ToolMetadata)
            if name not in self._registered_tools:
                self.register_tool(
                    name=name,
                    description=desc,
                    schema=schema,
                    executor=lambda **kwargs: None,  # placeholder
                    attested=False,
                )
            registered.append(name)

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": [
                    {"name": n, "registered": True} for n in registered
                ]
            },
        }

    def _handle_tools_call(
        self, params: dict[str, Any], msg_id: Any
    ) -> dict[str, Any]:
        """Handle tools/call: mediate through runtime monitor."""
        tool_name = params.get("name", "unknown")
        arguments = params.get("arguments", {})

        try:
            result = self.call_tool(tool_name, arguments)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": [{"type": "text", "text": str(result)}]},
            }
        except PermissionError as e:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32000,
                    "message": f"ProvShield denied: {e}",
                },
            }
        except ValueError as e:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32601,
                    "message": str(e),
                },
            }

    def get_registered_tools(self) -> dict[str, dict[str, Any]]:
        return dict(self._registered_tools)

    @property
    def tool_count(self) -> int:
        return len(self._registered_tools)
