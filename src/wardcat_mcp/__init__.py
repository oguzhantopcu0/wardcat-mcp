"""wardcat-mcp — an MCP server that exposes wardcat's on-prem PII detection as agent tools."""

from importlib.metadata import PackageNotFoundError, version

from wardcat_mcp.server import main

try:
    __version__ = version("wardcat-mcp")
except PackageNotFoundError:  # running from a source checkout, not installed
    __version__ = "0.1.0"

__all__ = ["main", "__version__"]
