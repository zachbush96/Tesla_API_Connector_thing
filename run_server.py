"""Offline stdio entry point. Never reads credentials or selects live transports."""
from tesla_connector import mcp
from tesla_connector.service import Service, Config
if __name__ == '__main__':
    mcp.Service = lambda: Service(Config())
    raise SystemExit(mcp.main())
