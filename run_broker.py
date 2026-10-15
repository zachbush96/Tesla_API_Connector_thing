#!/usr/bin/env python3
"""Manual foreground loopback mock only. Reads protected files only when owner launches."""
import argparse
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import TCPServer
from tesla_connector.broker import Broker
from tesla_connector.service import private_file, SafeError


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--operator-token-file',required=True)
    parser.add_argument('--mcp-token-file',required=True)
    parser.add_argument('--port',type=int,default=8765,help='Loopback port; 0 selects an ephemeral port for mock checks')
    parser.add_argument('--gateway-token-file',help='Dedicated read/preview gateway capability; owner provisioned')
    args=parser.parse_args()
    if args.port != 0 and not 1024 <= args.port <= 65535:parser.error('Invalid loopback port')
    broker=Broker('configured-owner',private_file(args.operator_token_file),private_file(args.mcp_token_file),gateway_token=private_file(args.gateway_token_file) if args.gateway_token_file else None)
    from tesla_connector.listener import serve_broker
    serve_broker(broker,args.port)

if __name__=='__main__':
    try:main()
    except (SafeError,OSError):raise SystemExit('Broker unavailable; configuration details withheld')
