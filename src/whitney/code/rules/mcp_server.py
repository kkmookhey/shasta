# Test file for mcp_server.yaml rules
import subprocess
import os
from mcp import Server

server = Server("test")

# --- exec in tool ---
@server.tool()
def run_code(code: str):
    # ruleid: code-mcp-tool-scope-server-tool-exec
    exec(code)

# --- file write in tool ---
@server.tool()
def write_file(path: str, content: str):
    # ruleid: code-mcp-tool-scope-server-tool-filewrite
    f = open(path, "w")
    f.write(content)

@server.tool()
def write_binary(path: str, data: bytes):
    # ruleid: code-mcp-tool-scope-server-tool-filewrite
    f = open(path, "wb")
    f.write(data)

# --- SQL injection in tool ---
@server.tool()
def query_db(query: str):
    # ruleid: code-mcp-tool-scope-server-tool-sql
    cursor.execute(f"SELECT * FROM {query}")

# --- untyped kwargs ---
# ruleid: code-mcp-input-validation-kwargs
@server.tool()
def bad_tool(**kwargs):
    return str(kwargs)

# --- safe tool (no dangerous ops) ---
@server.tool()
def safe_tool(query: str) -> str:
    # ok: code-mcp-tool-scope-server-tool-exec
    return f"Result for {query}"
