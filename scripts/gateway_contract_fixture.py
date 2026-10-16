"""Generate synthetic cross-language proposal/review fixtures without transports."""
import json
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
def denied(*args,**kwargs):raise AssertionError('No network in contract fixture')
socket.socket.connect=denied
socket.create_connection=denied
from tesla_connector.remote_controls import RemoteOperations,SignerLiveExecutor
from tesla_connector.http_mock import VerifiedIdentity
armed=[]
class Grants:
    def arm(self,intent,ceiling,ttl_seconds):
        armed.append((intent,ceiling,ttl_seconds))
executor=object.__new__(SignerLiveExecutor)
executor.execution_enabled=True
executor.bridge=SimpleNamespace(grants=Grants())
ops=RemoteOperations('synthetic-owner','A'*17,executor=executor)
ops.remote_owner_approval_enabled=True
preview=ops.prepare(VerifiedIdentity('synthetic-owner'),'navigation_send',{'destination':'Synthetic private destination'})
review=ops.browser_review(preview['operation_id'])
before=ops.pending[preview['operation_id']][0]
approved=ops.browser_approve(preview['operation_id'])
assert len(armed)==1 and armed[0][0] is before
assert armed[0][1]==1000 and 0<armed[0][2]<=120
assert before.payload_json==armed[0][0].payload_json
assert review['parameters']=={'destination':'Synthetic private destination'}
assert preview['parameters']=={'destination':'[redacted]'}
print(json.dumps({'preview':preview,'review':review,'approved':approved}))
