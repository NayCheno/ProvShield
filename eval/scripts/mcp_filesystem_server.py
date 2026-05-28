#!/usr/bin/env python3
"""Real MCP filesystem server over stdio (JSON-RPC 2.0).

Implements the Model Context Protocol for a sandboxed filesystem:
- initialize / initialized handshake
- tools/list: returns tool schemas
- tools/call: executes filesystem operations in a sandbox directory

This is a real MCP server that can be used with any MCP client.
All operations are confined to a sandbox directory for safety.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path


# Sandbox root — all operations confined here
_sandbox: Path | None = None


def _ensure_sandbox() -> Path:
    global _sandbox
    if _sandbox is None:
        _sandbox = Path(os.environ.get("MCP_SANDBOX", "")).resolve()
        if not _sandbox.exists():
            _sandbox = Path(os.environ.get("TEMP", "/tmp")) / "provshield_mcp_sandbox"
            _sandbox.mkdir(parents=True, exist_ok=True)
    return _sandbox


def _safe_path(path_str: str) -> Path:
    """Resolve path within sandbox, preventing directory traversal."""
    sandbox = _ensure_sandbox()
    target = (sandbox / path_str).resolve()
    if not str(target).startswith(str(sandbox)):
        raise PermissionError(f"Path traversal blocked: {path_str}")
    return target


# Tool implementations

def read_file(path: str, encoding: str = "utf-8") -> str:
    """Read a file from the sandbox."""
    p = _safe_path(path)
    if not p.exists():
        return f"Error: file not found: {path}"
    if not p.is_file():
        return f"Error: not a file: {path}"
    return p.read_text(encoding=encoding)


def write_file(path: str, content: str, encoding: str = "utf-8") -> str:
    """Write content to a file in the sandbox."""
    p = _safe_path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding=encoding)
    return f"Wrote {len(content)} bytes to {path}"


def list_directory(path: str = ".") -> str:
    """List files and directories in the sandbox."""
    p = _safe_path(path)
    if not p.exists():
        return f"Error: directory not found: {path}"
    if not p.is_dir():
        return f"Error: not a directory: {path}"
    entries = []
    for entry in sorted(p.iterdir()):
        kind = "dir" if entry.is_dir() else "file"
        size = entry.stat().st_size if entry.is_file() else 0
        entries.append(f"  [{kind}] {entry.name} ({size} bytes)")
    return "\n".join(entries) if entries else "(empty directory)"


def delete_file(path: str) -> str:
    """Delete a file from the sandbox."""
    p = _safe_path(path)
    if not p.exists():
        return f"Error: file not found: {path}"
    if p.is_dir():
        shutil.rmtree(p)
        return f"Deleted directory: {path}"
    p.unlink()
    return f"Deleted file: {path}"


def search_files(query: str, path: str = ".") -> str:
    """Search for files matching a pattern in the sandbox."""
    root = _safe_path(path)
    if not root.exists():
        return f"Error: directory not found: {path}"
    matches = []
    for p in root.rglob(f"*{query}*"):
        rel = p.relative_to(root)
        matches.append(str(rel))
    if not matches:
        return f"No files matching '{query}' found"
    return "\n".join(f"  {m}" for m in sorted(matches)[:50])


# MCP tool schemas
TOOLS = [
    {
        "name": "read_file",
        "description": "Read the contents of a file. Returns the file text.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative path to the file"},
                "encoding": {"type": "string", "default": "utf-8"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Write content to a file. Creates parent directories if needed.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative path for the file"},
                "content": {"type": "string", "description": "Content to write"},
                "encoding": {"type": "string", "default": "utf-8"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "list_directory",
        "description": "List files and directories at a path.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "default": ".", "description": "Directory path"},
            },
        },
    },
    {
        "name": "delete_file",
        "description": "Delete a file or directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to delete"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "search_files",
        "description": "Search for files matching a query string.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "path": {"type": "string", "default": ".", "description": "Root directory"},
            },
            "required": ["query"],
        },
    },
]

TOOL_EXECUTORS = {
    "read_file": read_file,
    "write_file": write_file,
    "list_directory": list_directory,
    "delete_file": delete_file,
    "search_files": search_files,
}

SERVER_INFO = {
    "name": "provshield-filesystem",
    "version": "1.0.0",
}


def handle_message(msg: dict) -> dict:
    """Handle a single JSON-RPC message."""
    method = msg.get("method", "")
    params = msg.get("params", {})
    msg_id = msg.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            },
        }

    if method == "notifications/initialized":
        # Notification — no response needed, but return ack for stdio
        return {"jsonrpc": "2.0", "id": msg_id, "result": None}

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"tools": TOOLS},
        }

    if method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        executor = TOOL_EXECUTORS.get(tool_name)
        if executor is None:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
            }
        try:
            result = executor(**arguments)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": [{"type": "text", "text": str(result)}]},
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32000, "message": str(e)},
            }

    # Unknown method
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32601, "message": f"Unknown method: {method}"},
    }


def main():
    """Run MCP server over stdio (newline-delimited JSON-RPC)."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        response = handle_message(msg)
        if response.get("id") is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
