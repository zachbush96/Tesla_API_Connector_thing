import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {webcrypto} from 'node:crypto';
import {gateway} from '../gateway/sites-gateway.mjs';
import {approval} from '../gateway/approval.mjs';
import {CONTROL_CATALOG,filterRemote,parseStrictJSON} from '../gateway/remote-control-tools.mjs';
globalThis.crypto??=webcrypto;
globalThis.fetch=()=>{throw Error('External network forbidden');};
const fixtureRun=spawnSync('python3',['-B',new URL('gateway_contract_fixture.py',import.meta.url).pathname],{encoding:'utf8'});
assert.equal(fixtureRun.status,0,fixtureRun.stderr);
const fixture=JSON.parse(fixtureRun.stdout),operation=fixture.preview.operation_id;
const catalog=JSON.parse(await readFile(new URL('../tesla_connector/control-catalog.json',import.meta.url),'utf8'));
assert.deepEqual(CONTROL_CATALOG,catalog);assert.equal(Object.keys(catalog).length,43);
const env={IDENTITY_BOUNDARY:'sites',OWNER_USER_ID:'synthetic-owner',GATEWAY_PUBLIC_ORIGIN:'https://gateway.example.test',
 BROKER_URL:'https://broker.example.test/mcp',BROKER_GATEWAY_TOKEN:'a'.repeat(48),
 ACCESS_CLIENT_ID:'b'.repeat(32),ACCESS_CLIENT_SECRET:'c'.repeat(48),REMOTE_CONTROL_MODE:'live',REMOTE_OWNER_APPROVAL:'enabled'};
const request=(name,args={},owner='synthetic-owner')=>new Request(env.GATEWAY_PUBLIC_ORIGIN+'/mcp',{
 method:'POST',headers:{'Content-Type':'application/json',Accept:'application/json','oai-authenticated-user-id':owner},
 body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name,arguments:args}})});
let calls=0,approved=false;
const fake=async(url,options)=>{
 calls++;assert.equal(url,env.BROKER_URL);assert.equal(options.redirect,'manual');
 assert.equal(options.headers.Authorization,'Bearer '+env.BROKER_GATEWAY_TOKEN);
 const rpc=JSON.parse(options.body);
 if(rpc.method==='owner/control/review')return Response.json({jsonrpc:'2.0',id:1,result:fixture.review});
 if(rpc.method==='owner/control/approve'){
  if(approved)return new Response(null,{status:409});
  approved=true;return Response.json({jsonrpc:'2.0',id:1,result:fixture.approved});
 }
 assert.equal(rpc.method,'tools/call');
 return Response.json({jsonrpc:'2.0',id:1,result:{isError:false,content:[{type:'text',text:JSON.stringify({...fixture.preview,private_extra:'MUST_NOT_ESCAPE'})}]}});
};
let response=await gateway(request('prepare_navigation_send',{destination:'Synthetic private destination'}),env,fake);
let body=await response.json(),proposal=JSON.parse(body.result.content[0].text);
assert.equal(response.status,200);assert.equal(calls,1);
assert.equal(proposal.approval_url,env.GATEWAY_PUBLIC_ORIGIN+'/approve/'+operation);
assert.equal(proposal.parameters.destination,'[redacted]');
assert(!JSON.stringify(proposal).includes('MUST_NOT_ESCAPE'));
assert.equal((await gateway(request('prepare_lock',{},'another-owner'),env,fake)).status,403);assert.equal(calls,1);
assert((await (await gateway(request('prepare_lock'),{...env,BROKER_URL:undefined},fake)).json()).result.isError);
assert.equal(calls,1);
assert((await (await gateway(request('owner/control/approve',{operation_id:operation}),env,fake)).json()).result.isError);
assert.equal(calls,1);
const page=await approval(new Request(env.GATEWAY_PUBLIC_ORIGIN+'/approve/'+operation,{headers:{'oai-authenticated-user-id':'synthetic-owner'}}),env,fake);
assert.equal(page.status,200);const cookie=page.headers.get('Set-Cookie').split(';')[0];
assert(cookie.startsWith('__Host-connector_approve='));assert(page.headers.get('Set-Cookie').includes('HttpOnly'));
const browser=(action,cookieValue=cookie,origin=env.GATEWAY_PUBLIC_ORIGIN,owner='synthetic-owner')=>new Request(env.GATEWAY_PUBLIC_ORIGIN+'/approve/'+operation+'/'+action,{
 method:'POST',headers:{'Content-Type':'application/json',Origin:origin,'Sec-Fetch-Site':'same-origin',Cookie:cookieValue,'oai-authenticated-user-id':owner},
 body:JSON.stringify(action==='review'?{}:{motorized_port_confirmed:false})});
assert.equal((await approval(browser('approve',cookie+'bad'),env,fake)).status,403);
assert.equal((await approval(browser('approve',cookie,'https://foreign.example.test'),env,fake)).status,403);
assert.equal((await approval(browser('approve',cookie,env.GATEWAY_PUBLIC_ORIGIN,'another-owner'),env,fake)).status,403);
assert.equal(calls,1);
response=await approval(browser('review'),env,fake);
assert.deepEqual((await response.json()).parameters,{destination:'Synthetic private destination'});
response=await approval(browser('approve'),env,fake);
assert.equal((await response.json()).approved,true);assert(response.headers.get('Set-Cookie').includes('Max-Age=0'));
assert.equal((await approval(browser('approve'),env,fake)).status,409);
assert.equal((await approval(browser('approve'),{...env,REMOTE_OWNER_APPROVAL:'disabled'},fake)).status,503);
const receipt={action:'lock',simulated:false,submitted:true,accepted:true,success_evidence:'vehicle_command_reported_success',
 resulting_state_verified:false,vehicle_execution_verified:false,execution_enabled:true,sdk_commit:'49977a18fd68567501d59e16a6c9e4a8b9348544',
 fleet_network_requests:2,gross_reserved_microdollars:2000,prerequisite_data_requests:0,prerequisite_gross_reserved_microdollars:0,total_gross_reserved_microdollars:2000};
assert.deepEqual(filterRemote('execute_control',receipt,{operation_id:operation},'live'),receipt);
assert.throws(()=>filterRemote('execute_control',{...receipt,resulting_state_verified:true},{operation_id:operation},'live'));
assert.throws(()=>parseStrictJSON('{"a":1,"a":2}'));
const built=(await import('../dist/gateway.mjs')).default;
const discovery=await built.fetch(new Request(env.GATEWAY_PUBLIC_ORIGIN+'/browser-discovery',{
 method:'POST',headers:{'Content-Type':'application/json',Accept:'application/json',Origin:env.GATEWAY_PUBLIC_ORIGIN,'Sec-Fetch-Site':'same-origin','oai-authenticated-user-id':'synthetic-owner'},
 body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list',params:{}})}),env);
const tools=(await discovery.json()).result.tools;
assert.equal(tools.filter(t=>t.name.startsWith('prepare_')&&t.name!=='prepare_control').length,43);
console.log('PASS: current Python navigation proposal/review binding, 43-action gateway, receipt limits, private owner UI/cookie/origin/replay checks and built browser discovery; fake broker only');
