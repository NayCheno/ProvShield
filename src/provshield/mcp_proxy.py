"""MCP proxy: intercepts tool registration and mediates tool calls.

This is a skeleton implementation that demonstrates the proxy architecture.
A production implementation would integrate with the actual MCP protocol.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from .context import ContextBuilder
from .monitor import RuntimeMonitor, register_tool
from .types import Effect, NormalizedToolCall, Sink


class MCPProxy:
    """Proxy between MCP client and MCP servers.

    Responsibilities:
      - Intercept tool registration and label metadata
      - Mediate all tool calls through the runtime monitor
      - Label tool outputs
      - Apply network and filesystem guardrails
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

    def get_registered_tools(self) -> dict[str, dict[str, Any]]:
        return dict(self._registered_tools)

    @property
    def tool_count(self) -> int:
        return len(self._registered_tools)
