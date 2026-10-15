"""Foreground loopback broker listener; no request logging."""
import json
import threading
import select
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import TCPServer, ThreadingMixIn

def _peer_disconnected(connection):
    """Check plaintext loopback EOF without waiting or consuming request bytes."""
    try:
        if not select.select([connection],[],[],0)[0]:
            return False
        return connection.recv(1,socket.MSG_PEEK|socket.MSG_DONTWAIT)==b''
    except Exception:
        return True

def serve_broker(broker, port=8765):
    class Handler(BaseHTTPRequestHandler):
        server_version='HamBroker'
        sys_version=''
        def log_message(self,*args):pass  # Callback query and authorization never logged.
        def request(self):
            try:
                if any(len(self.headers.get_all(k,[]))>1 for k in ('Host','Authorization','Cookie','Origin','Content-Length','Content-Type','X-Connector-Signer-Deadline-Ms')) or self.headers.get('Transfer-Encoding'):
                    raise ValueError()
                length=int(self.headers.get('Content-Length','0'))
                if length<0 or length>65536:raise ValueError()
                body=self.rfile.read(length)
                if len(body)!=length:raise ValueError()
                arguments = {}
                if self.path.startswith('/internal/signer/'):
                    def cancelled():
                        # Go closes this plaintext loopback connection when its
                        # context is canceled. Inspect EOF without consuming data.
                        return _peer_disconnected(self.connection)
                    arguments['request_cancelled'] = cancelled
                status,headers,data=broker.handle(self.command,self.path,{k.lower():v for k,v in self.headers.items()},body,**arguments)
            except Exception:
                status,headers,data=400,{'Cache-Control':'no-store'},{'error':'Request refused'}
            encoded=b'' if data is None else json.dumps(data,allow_nan=False).encode()
            self.send_response(status)
            for k,v in headers.items():self.send_header(k,v)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(encoded)))
            self.send_header('Connection','close')
            self.end_headers()
            if self.command != 'HEAD':self.wfile.write(encoded)
        do_GET=request
        do_POST=request
        do_HEAD=request
        do_PUT=request
        do_DELETE=request
        def setup(self):
            super().setup();self.connection.settimeout(5)
    # The signer calls back while /mcp is waiting. Bounded parallel loopback
    # handling prevents that reentrant flow from blocking its own callback.
    class LoopbackServer(ThreadingMixIn,HTTPServer):
        daemon_threads=True
        block_on_close=False
        slots=threading.BoundedSemaphore(16)
        def process_request(self,request,address):
            if not self.slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            try:super().process_request(request,address)
            except BaseException:
                self.slots.release()
                raise
        def process_request_thread(self,request,address):
            try:super().process_request_thread(request,address)
            finally:self.slots.release()
        def handle_error(self,request,address):pass  # Never print raw handler exceptions.
        def server_bind(self):
            TCPServer.server_bind(self)
            self.server_name='localhost'
            self.server_port=self.socket.getsockname()[1]
    with LoopbackServer(('127.0.0.1',port),Handler) as server:
        broker.local_host=f'127.0.0.1:{server.server_port}'
        commands=bool(getattr(getattr(broker,'signer_bridge',None),'execution_enabled',False))
        print(f'Broker ready on {broker.local_host}; mode={broker.mcp.service.config.mode}; commands_enabled={commands}',flush=True)
        server.serve_forever()
