import assert from 'node:assert/strict';
import {gateway} from '../gateway/sites-gateway.mjs';
import {parseStrictJSON} from '../gateway/remote-control-tools.mjs';
globalThis.fetch=()=>{throw Error('External network forbidden');};
const env={IDENTITY_BOUNDARY:'sites',OWNER_USER_ID:'synthetic-owner',
 BROKER_URL:'https://broker.example.test/mcp',BROKER_GATEWAY_TOKEN:'a'.repeat(48),
 ACCESS_CLIENT_ID:'b'.repeat(32),ACCESS_CLIENT_SECRET:'c'.repeat(48)};
const request=(name,args={},owner='synthetic-owner')=>new Request('https://gateway.example.test/mcp',{
 method:'POST',headers:{'Content-Type':'application/json',Accept:'application/json','oai-authenticated-user-id':owner},
 body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name,arguments:args}})});
let calls=0;
const fake=async(url,options)=>{
 calls++;assert.equal(url,env.BROKER_URL);assert.equal(options.redirect,'manual');
 assert.equal(options.headers.Authorization,'Bearer '+env.BROKER_GATEWAY_TOKEN);
 return Response.json({jsonrpc:'2.0',id:1,result:{isError:false,content:[{type:'text',text:JSON.stringify({
 mode:'mock',battery_percent:72,charging_state:'Disconnected',charge_limit_percent:80,charger_power_kw:0,
 private_extra:'MUST_NOT_ESCAPE'})}]}});
};
let response=await gateway(request('read_battery_charging'),env,fake);
let body=await response.text();
assert.equal(response.status,200);assert.equal(calls,1);assert(!body.includes('MUST_NOT_ESCAPE'));
assert.equal((await gateway(request('read_battery_charging',{},'another-owner'),env,fake)).status,403);
assert.equal(calls,1);
response=await gateway(request('read_battery_charging'),{...env,BROKER_URL:undefined},fake);
assert((await response.json()).result.isError);assert.equal(calls,1);
response=await gateway(request('execute_control',{operation_id:'d'.repeat(32)}),{...env,REMOTE_CONTROL_MODE:'live'},fake);
assert.equal(response.status,503);assert.equal(calls,1);
assert.throws(()=>parseStrictJSON('{"a":1,"a":2}'));
console.log('PASS: gateway identity, placeholder refusal, output filtering, redirect policy and explicit live-mode refusal; no external network');
