// Sites-only gateway. Tesla authorization and read allowances remain on the Mac.
import {handle as validate, tools as mockTools, boundedBody} from './worker.mjs';
import {filterRemote,parseStrictJSON,LIVE_REMOTE_TOOLS,remoteMode} from './remote-control-tools.mjs';
function brokerTarget(env){
 const target=new URL(env.BROKER_URL??'https://broker.example.invalid/mcp');
 if(target.protocol!=='https:'||target.username||target.password||target.pathname!=='/mcp'||target.search||target.hash||target.hostname.endsWith('.invalid'))throw Error('Configure owner broker URL');
 return target.href;
}
const object=x=>x!==null && typeof x==='object' && !Array.isArray(x);
const reply=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store'}});
const descriptions={
 read_battery_charging:'READ: filtered battery and charging only; synthetic in mock mode. Live reads require the Mac\'s saved authorization and existing allowance.',
 read_temperature:'READ: cabin temperature and vehicle timestamp only; synthetic in mock mode. No HVAC change or wake; live reads require the Mac\'s saved authorization and existing allowance.',
 read_location:'READ: coarse location only; synthetic in mock mode. Live reads require the Mac\'s saved authorization and existing allowance.',
};
const tools=mockTools.map(t=>({...t,description:descriptions[t.name]??t.description}));
const toolsFor=env=>remoteMode(env)==='live'?tools.map(t=>LIVE_REMOTE_TOOLS.find(x=>x.name===t.name)??t):tools;
function exceptionDiagnostic(error){
 const error_name=['TypeError','AbortError','TimeoutError','Error'].includes(error?.name)?error.name:'other';
 // Inspect a bounded message privately. Only an unambiguous fixed label escapes.
 const message=typeof error?.message==='string'?error.message.slice(0,2048):'';
 const patterns={
  runtime_invocation:/Illegal invocation|incompatible receiver/iu,
  redirect_refused:/redirect (?:mode (?:(?:is|was) )?(?:set to )?["']?error|(?:was |is )?(?:refused|disallowed|not allowed))|unexpected redirect|redirect encountered/iu,
  network_policy:/(?:blocked|denied) by (?:the )?(?:network|egress) policy|(?:destination|hostname|host) (?:is )?not (?:allowed|allowlisted)/iu,
  dns:/\b(?:ENOTFOUND|EAI_AGAIN)\b|DNS (?:resolution|lookup) (?:failed|failure)|getaddrinfo failed/iu,
  tls:/TLS handshake (?:failed|failure)|SSL handshake (?:failed|failure)|certificate (?:verification failed|has expired)|\bCERT_HAS_EXPIRED\b/iu,
  connection:/\b(?:ECONNREFUSED|ECONNRESET|ENETUNREACH|EHOSTUNREACH)\b|connection (?:refused|reset)|network is unreachable/iu,
 };
 const matches=Object.entries(patterns).filter(([,pattern])=>pattern.test(message));
 return {error_name,network_subtype:matches.length===1?matches[0][0]:'unknown'};
}
const failure=(id,modern=false,classification='configuration',status,exception)=>{
 const diagnostic={failure_class:classification,retry:false,...(classification==='status'&&Number.isInteger(status)&&status>=100&&status<=599?{upstream_status:status}:{}),...(['network','timeout'].includes(classification)&&exception?exceptionDiagnostic(exception):{})};
 return reply({jsonrpc:'2.0',id,result:{...(modern?{resultType:'complete'}:{}),content:[{type:'text',text:JSON.stringify(diagnostic)}],structuredContent:diagnostic,isError:true}});
};
const credential=value=>typeof value==='string'&&value.length>=16&&value.length<=4096&&/^[!-~]+$/u.test(value);
function setup(env){
 const missing=[];
 if(env.IDENTITY_BOUNDARY!=='sites'||typeof env.OWNER_USER_ID!=='string'||!env.OWNER_USER_ID.trim())missing.push('verified_owner_identity');
 if(!credential(env.BROKER_GATEWAY_TOKEN))missing.push('private_mac_gateway_credential');
 if(['ACCESS_CLIENT_ID','ACCESS_CLIENT_SECRET'].some(k=>!credential(env[k])))missing.push('cloudflare_routing_credentials');
 return {gateway:'online',vehicle_connection:'not_verified',vehicle_commands:remoteMode(env)==='live'?'configured-live; vehicle readiness unverified':'disabled',missing_configuration:missing,
 next_steps:[
 missing.includes('verified_owner_identity')?'Configure the verified Site-scoped owner identity through Sites; never substitute an email or guessed ID.':'The Site-scoped owner identity is configured. Preserve the private audience and owner checks.',
 missing.includes('cloudflare_routing_credentials')?'Configure the owner-provisioned dedicated Cloudflare service credentials through supported Site secret settings. Never paste them into chat.':'Cloudflare routing credentials are configured. Verify the owner-provisioned protected tunnel without regenerating credentials.',
 missing.includes('private_mac_gateway_credential')?'Configure the dedicated gateway credential through supported Site secret settings; keep Tesla authorization on the Mac.':remoteMode(env)==='live'?'The dedicated Mac gateway credential is configured. A live command also requires matching execution modes and an expiring one-action grant on the Mac.':'The dedicated Mac gateway credential is configured. Keep it scoped to reads, previews and physically disabled SDK mock tools.',
 'Route only your configured BROKER_URL /mcp to loopback port 8765; enforce a separate Access policy for the owner review page.',
 'Start the owner-configured Mac broker and tunnel, then verify an allowed read through this installed plugin. A setup check does not verify the car.',
 'Reuse valid saved Tesla authorization; do not repeat consent or overwrite it. Check the existing read allowance before a live read, and obtain approval before any new paid allowance. Virtual-key pairing and live commands remain separate.']};
}
function number(value,min,max){if(typeof value!=='number'||!Number.isFinite(value)||value<min||value>max)throw Error();return value;}
function filtered(name,data,args,mode){
 if(['prepare_control','execute_control'].includes(name))return filterRemote(name,data,args,mode);
 if(!object(data))throw Error();
 if(name==='read_temperature'){
  if(!['mock','live-read'].includes(data.mode)||!Number.isSafeInteger(data.vehicle_timestamp_ms)||data.vehicle_timestamp_ms<0||data.vehicle_timestamp_ms>9999999999999)throw Error();
  const celsius=number(data.inside_celsius,-60,100);
  return {mode:data.mode,inside_celsius:celsius,inside_fahrenheit:Math.round((celsius*9/5+32)*10)/10,vehicle_timestamp_ms:data.vehicle_timestamp_ms,synthetic:data.mode==='mock'};
 }
 if(name==='read_battery_charging') {
  if(!['mock','live-read'].includes(data.mode)||!['Charging','Disconnected','Complete','Stopped','Starting','NoPower','Unknown'].includes(data.charging_state))throw Error();
  return {mode:data.mode,battery_percent:number(data.battery_percent,0,100),charging_state:data.charging_state,charge_limit_percent:number(data.charge_limit_percent,0,100),charger_power_kw:number(data.charger_power_kw,0,1000)};
 }
 if(name==='read_location') {
  if(!['mock','live-read'].includes(data.mode))throw Error();
  return {mode:data.mode,latitude_approx:Math.round(number(data.latitude_approx,-90,90)*10)/10,longitude_approx:Math.round(number(data.longitude_approx,-180,180)*10)/10,precision:'0.1 degree; sensitive, do not persist',synthetic:data.mode==='mock'};
 }
 if(data.dry_run!==true||data.executed!==false)throw Error();
 if(name==='preview_navigation' && data.command==='navigation_request')return {dry_run:true,executed:false,command:'navigation_request',destination:'[redacted]'};
 if(name==='preview_temperature' && data.command==='set_temps')return {dry_run:true,executed:false,command:'set_temps',celsius:number(data.celsius,15,28)};
 throw Error();
}
export async function gateway(request,env={},fetcher=(...args)=>globalThis.fetch(...args)){
 if(env.REMOTE_CONTROL_MODE==='live')return new Response('Public gateway reference is mock-only; live adapter requires review',{status:503});
 // Existing strict handler validates Sites identity, Origin, JSON body, tool name/args.
 const validated=await validate(request.clone(),env);
 if(validated.status!==200)return validated;
 const validation=await validated.json();
 if(!validation.result||validation.result.isError)return reply(validation);
 const message=parseStrictJSON(await boundedBody(request));
 const modern=message.params?._meta?.['io.modelcontextprotocol/protocolVersion']==='2026-07-28'||request.headers.get('mcp-protocol-version')==='2026-07-28';
 const complete=modern?{resultType:'complete'}:{};
 if(message.method==='tools/call'&&message.params.name==='check_setup')return reply({jsonrpc:'2.0',id:message.id,result:{...complete,content:[{type:'text',text:JSON.stringify(setup(env))}],isError:false}});
 if(message.method==='tools/list')return reply({jsonrpc:'2.0',id:message.id,result:{...complete,tools:toolsFor(env)}});
 if(message.method!=='tools/call') {
  if(message.method==='server/discover')validation.result._meta['io.modelcontextprotocol/serverInfo']={name:'tesla-connector-sites-gateway',version:'0.2.0'};
  if(message.method==='initialize')validation.result.serverInfo={name:'tesla-connector-sites-gateway',version:'0.1.0'};
  return reply(validation);
 }
 const names=['BROKER_GATEWAY_TOKEN','ACCESS_CLIENT_ID','ACCESS_CLIENT_SECRET'];
 if(names.some(k=>!credential(env[k])))return failure(message.id,modern);
 // The public schema accepts only the operation ID. This trusted mode assertion
 // is added after strict validation; the Mac must reject a mismatch before
 // consuming an intent, reserving budget, or calling its executor. Response
 // filtering alone is too late to prevent a physical command.
 const mode=remoteMode(env);
 const params={name:message.params.name,arguments:message.params.name==='execute_control'
  ?{...message.params.arguments,expected_control_mode:mode}
  :message.params.arguments??{}};
 let stage='network';
 // Live execution includes bounded facts, SDK Park query and action phases.
 // An expired response remains uncertain and must never trigger a retry.
 const signal=AbortSignal.timeout(params.name==='execute_control'&&mode==='live'?65000:10000);
 try {
  const response=await fetcher(brokerTarget(env),{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json',
   'Authorization':'Bearer '+env.BROKER_GATEWAY_TOKEN,'CF-Access-Client-Id':env.ACCESS_CLIENT_ID,'CF-Access-Client-Secret':env.ACCESS_CLIENT_SECRET},
   body:JSON.stringify({jsonrpc:'2.0',id:message.id,method:'tools/call',params}),redirect:'manual',signal});
  // Manual mode never follows redirects. Reject status before headers or body.
  if(response.status!==200)return failure(message.id,modern,'status',response.status);
  if(response.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase()!=='application/json')return failure(message.id,modern,'contenttype');
  stage='protocol';
  const output=parseStrictJSON(await boundedBody(response));
  if(!object(output)||output.jsonrpc!=='2.0'||output.id!==message.id||output.result?.isError!==false||!Array.isArray(output.result.content)||output.result.content.length!==1||output.result.content[0].type!=='text')throw Error();
  const data=parseStrictJSON(output.result.content[0].text);
  stage='filter';
  const result=filtered(params.name,data,params.arguments,mode);
  return reply({jsonrpc:'2.0',id:message.id,result:{...complete,content:[{type:'text',text:JSON.stringify(result)}],isError:false}});
 } catch(error){return failure(message.id,modern,signal.aborted||error?.name==='TimeoutError'?'timeout':stage,undefined,error);} // No body, header, URL, token or exception logging.
}
export default {fetch:(request,env)=>gateway(request,env)};
