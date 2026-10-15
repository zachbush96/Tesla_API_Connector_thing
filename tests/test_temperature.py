import json
import unittest
from unittest.mock import Mock, MagicMock
from tesla_connector.service import Config, Service, FleetReader, SafeError
from tesla_connector.broker import Broker

class TemperatureTests(unittest.TestCase):
    def test_mock_broker_temperature_and_auth(self):
        broker=Broker('owner','o'*32,'m'*32,gateway_token='g'*32)
        message=json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'read_temperature','arguments':{}}}).encode()
        headers={'host':'127.0.0.1:8765','content-type':'application/json','authorization':'Bearer '+'g'*32}
        status,_,body=broker.handle('POST','/mcp',headers,message)
        self.assertEqual(status,200)
        result=json.loads(body['result']['content'][0]['text'])
        self.assertEqual(result,{'mode':'mock','inside_celsius':19.0,'inside_fahrenheit':66.2,'vehicle_timestamp_ms':1700000000000,'synthetic':True})
        self.assertEqual(broker.handle('POST','/mcp',{**headers,'authorization':'Bearer wrong'},message)[0],401)
        bad=json.dumps({'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'read_temperature','arguments':{'wake':True}}}).encode()
        self.assertTrue(broker.handle('POST','/mcp',headers,bad)[2]['result']['isError'])

    def test_filtered_live_reader_get_only(self):
        config=Config('live-read',True)
        reader=FleetReader(config,credential_provider=lambda endpoint:('A'*17,'synthetic-token'))
        opener=MagicMock();reader.opener=opener
        opener.open.return_value.__enter__.return_value.read.return_value=json.dumps({'response':{'climate_state':{'inside_temp':19,'timestamp':1791462230999,'private':'removed'},'vin':'removed'}}).encode()
        result=Service(config,reader).call('read_temperature',{})
        self.assertEqual(result['inside_fahrenheit'],66.2)
        self.assertFalse(result['synthetic']);self.assertNotIn('private',json.dumps(result));self.assertNotIn('vin',result)
        request=opener.open.call_args.args[0]
        self.assertEqual(request.get_method(),'GET');self.assertTrue(request.full_url.endswith('/vehicle_data?endpoints=climate_state'))
        self.assertEqual(opener.open.call_count,1)

    def test_missing_invalid_and_timestamp_refusal(self):
        reader=Mock();service=Service(Config(),reader)
        for value in (None,True,float('nan'),101,-61,'19'):
            reader.data.return_value={'climate_state':{'inside_temp':value,'timestamp':1700000000000}}
            with self.assertRaises(SafeError):service.call('read_temperature',{})
        for stamp in (None,True,-1,1.2,'1700000000000'):
            reader.data.return_value={'climate_state':{'inside_temp':19,'timestamp':stamp}}
            with self.assertRaises(SafeError):service.call('read_temperature',{})
        reader.reset_mock()
        with self.assertRaises(SafeError):service.call('read_temperature',{'wake':True})
        reader.data.assert_not_called()

    def test_live_broker_requires_explicit_composition(self):
        reader=Mock();reader.data.return_value={'climate_state':{'inside_temp':19,'timestamp':1791462230999}}
        service=Service(Config('live-read',True),reader)
        with self.assertRaises(SafeError):Broker('owner','o'*32,'m'*32,service=service)
        reader.data.assert_not_called()
        broker=Broker('owner','o'*32,'m'*32,gateway_token='g'*32,service=service,allow_live_reads=True)
        message=json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'read_temperature','arguments':{}}}).encode()
        status,_,body=broker.handle('POST','/mcp',{'host':'127.0.0.1:8765','content-type':'application/json','authorization':'Bearer '+'g'*32},message)
        self.assertEqual(status,200);result=json.loads(body['result']['content'][0]['text'])
        self.assertEqual(result['mode'],'live-read');self.assertFalse(result['synthetic'])
        reader.data.assert_called_once_with('climate_state')
