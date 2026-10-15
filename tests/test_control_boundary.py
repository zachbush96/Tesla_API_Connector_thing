import json
import unittest
from tesla_connector.broker import Broker,ORIGIN
from tesla_connector.controls import OwnerControlWorkflow
from tesla_connector.commands import ApprovalLedger
from tesla_connector.service import SafeError

class ControlBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.workflow=OwnerControlWorkflow('synthetic-owner','AAAAAAAAAAAAAAAAA',ApprovalLedger())
        self.broker=Broker('synthetic-owner','o'*32,'m'*32,gateway_token='g'*32,control_workflow=self.workflow)
        self.headers={'host':'connector.example.invalid','origin':ORIGIN,'authorization':'Bearer '+'o'*32}
        status,headers,body=self.broker.handle('POST','/operator/session',self.headers)
        self.assertEqual(status,200)
        self.browser={**self.headers,'cookie':headers['Set-Cookie'].split(';')[0],'x-csrf-token':body['csrf'],'content-type':'application/json'}
    def post(self,path,data,headers=None):return self.broker.handle('POST',path,headers or self.browser,json.dumps(data).encode())
    def test_owner_exact_review_approve_has_no_execution_route(self):
        status,_,prepared=self.post('/operator/control/prepare',{'action':'navigation_send','arguments':{'destination':'Synthetic private destination'}})
        self.assertEqual(status,200);self.assertNotIn('Synthetic private destination',json.dumps(prepared))
        ref=prepared['intent_id']
        status,_,review=self.post('/operator/control/review',{'intent_id':ref})
        self.assertEqual(status,200);self.assertIn('Synthetic private destination',json.dumps(review))
        status,_,approved=self.post('/operator/control/approve',{'intent_id':ref,'review_sha256':review['review_sha256']})
        self.assertEqual(status,200);self.assertFalse(approved['executed']);self.assertFalse(approved['execution_enabled'])
        self.assertEqual(self.post('/operator/control/execute',{'approval_ticket':approved['approval_ticket']})[0],404)
        self.assertEqual(self.post('/operator/control/approve',{'intent_id':ref,'review_sha256':review['review_sha256']})[0],400)
    def test_model_and_gateway_credentials_cannot_mint_owner_session(self):
        for token in ('m'*32,'g'*32):
            self.assertEqual(self.broker.handle('POST','/operator/session',{**self.headers,'authorization':'Bearer '+token})[0],403)
            headers={'host':'connector.example.invalid','authorization':'Bearer '+token,'content-type':'application/json'}
            self.assertEqual(self.post('/operator/control/prepare',{'action':'lock','arguments':{}},headers)[0],401)
    def test_csrf_origin_and_json_confirmation_flags_rejected(self):
        for headers in ({**self.browser,'x-csrf-token':'wrong'},{**self.browser,'origin':'https://untrusted.invalid'}):
            self.assertEqual(self.post('/operator/control/prepare',{'action':'lock','arguments':{}},headers)[0],403)
        self.assertEqual(self.post('/operator/control/prepare',{'action':'unlock','arguments':{},'confirmed':True})[0],404)
        raw=b'{"action":"lock","action":"unlock","arguments":{}}'
        self.assertEqual(self.broker.handle('POST','/operator/control/prepare',self.browser,raw)[0],400)
    def test_default_live_launcher_has_no_review_authority(self):
        plain=Broker('synthetic-owner','o'*32,'m'*32)
        status,headers,body=plain.handle('POST','/operator/session',self.headers)
        browser={**self.browser,'cookie':headers['Set-Cookie'].split(';')[0],'x-csrf-token':body['csrf']}
        self.assertEqual(plain.handle('POST','/operator/control/prepare',browser,b'{}')[0],503)
        with self.assertRaises(SafeError):Broker('different-owner','o'*32,'m'*32,control_workflow=self.workflow)
