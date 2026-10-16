// Sites-only gateway. Tesla authorization and read allowances remain on the Mac.
import {handle as validate, tools as mockTools, boundedBody} from './worker.mjs';
import {filterRemote,parseStrictJSON,LIVE_REMOTE_TOOLS,remoteMode} from './remote-control-tools.mjs';
import {brokerTarget,publicOrigin} from './config.mjs';
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
// Broker/signing evidence crosses the Site boundary only after an exact schema
// check. Unknown fields or unsafe values omit the whole optional evidence object.
// Tool error text remains private even when its MCP envelope is well formed.
const diagnosticStages=["authenticated_session_ready","http_initiated","operation_failed","operation_started","operation_succeeded","request_written","reservation_acknowledged","reservation_attempted","response_received","response_validated"];
const pythonExceptions=["python_connection_refused","python_connection_reset","python_content_type","python_dns_error","python_http_error","python_http_status","python_incomplete_read","python_journal_error","python_json_invalid","python_other","python_response_too_large","python_ssl_error","python_timeout","python_tls_certificate","python_url_error","python_validation"];
const diagnosticExceptions=["bridge_refused","command_ack_missing","command_cache_invalid","command_cache_missing","command_decryption_failed","command_exchange_failed","command_metadata_invalid","command_nonce_length","command_payload_invalid","command_payload_missing","command_status_missing","command_status_reason","command_status_rejected","command_status_unknown_fields","command_tag_length","context_canceled","context_deadline","fleet_envelope_error","fleet_envelope_invalid_base64","fleet_envelope_invalid_json","fleet_envelope_invalid_shape","fleet_envelope_too_large","fleet_response_missing","guard_handshake_retry_blocked","http_status","json_invalid","local_refused","network_dns","network_error","network_refused","network_reset","network_timeout","none","python_connection_refused","python_connection_reset","python_content_type","python_dns_error","python_http_error","python_http_status","python_incomplete_read","python_journal_error","python_json_invalid","python_other","python_response_too_large","python_ssl_error","python_timeout","python_tls_certificate","python_url_error","python_validation","response_content_type","response_read_error","response_too_large","routable_destination_length","routable_destination_mismatch","routable_destination_missing","routable_destination_type","routable_domain_mismatch","routable_invalid_protobuf","routable_source_missing","routable_source_type","routable_status_error","routable_status_unknown","routable_status_wait","routable_unknown_fields","routable_uuid_length","routable_uuid_mismatch","routable_uuid_missing","sdk_authentication","sdk_bad_response","sdk_busy","sdk_error","sdk_invalid_public_key","sdk_key_not_paired","sdk_no_decryption_context","sdk_no_session","sdk_nominal_error","sdk_not_connected","sdk_protocol_unsupported","sdk_replayed_response","sdk_requires_ble","sdk_requires_encryption","sdk_requires_key","sdk_routable_fault","sdk_unexpected_public_key","sdk_unknown","session_info_exchange_failed","session_info_hmac_failed","session_info_hmac_mismatch","session_info_invalid_protobuf","session_info_invalid_public_key","session_info_late","session_info_missing","session_info_status_unknown","session_info_tag_length","session_info_tag_missing","session_info_unknown_fields","tls_certificate","tls_handshake","vehicle_rejected"];
const diagnosticKinds=["command","handshake","navigation","operation","state_handshake","state_query"];
const diagnosticCategories=["authentication","bridge","context","fleet","http","local","none","response","routable","sdk","tls","transport","vehicle"];
const diagnosticVehicleErrors=["account_credentials_required","bad_parameter","busy","decoding","expiry_too_long","identity_missing","inactive_key","incorrect_epoch","insufficient_privileges","internal","invalid_command","invalid_counter","invalid_domain","invalid_iv","invalid_key","invalid_key_handle","invalid_session","invalid_signature","keychain_full","malformed_response","metadata_hash","none","not_whitelisted","rejected","remote_access_disabled","remote_service_access_disabled","repeated_counter","request_expired","request_mtu","response_encryption_required","response_mtu","timeout","unclassified","unknown_fault","unknown_key","wrong_personalization"];
const diagnosticLegacyFlags=["authenticated_session_ready","http_initiated","request_written","reservation_acknowledged","response_received"];
const diagnosticFlags=["authenticated_session_ready","checkpoint_persistence_failed","http_initiated","local_finalization_failed","request_written","reservation_acknowledged","response_received"];
const diagnosticBaseFields=['stage','failure_stage','kind','exception_type','category','http_status','vehicle_error'];
const exactKeys=(value,keys)=>object(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
const diagnosticStatus=value=>Number.isInteger(value)&&(value===0||(value>=100&&value<=599));
function safeUpstreamDiagnostic(value){
 if(!object(value)||value.error_category!=='upstream_tool'||Object.keys(value).some(key=>!['error_category','diagnostic','local_transport'].includes(key)))return;
 const result={error_category:'upstream_tool'};
 if(Object.hasOwn(value,'diagnostic')){
  const original=value.diagnostic;
  const d=exactKeys(original,[...diagnosticBaseFields,...diagnosticLegacyFlags])
   ?{...original,checkpoint_persistence_failed:false,local_finalization_failed:false}:original;
  if(!exactKeys(d,[...diagnosticBaseFields,...diagnosticFlags])||!diagnosticStages.includes(d.stage)||!['none',...diagnosticStages].includes(d.failure_stage)||!diagnosticKinds.includes(d.kind)||!diagnosticExceptions.includes(d.exception_type)||!diagnosticCategories.includes(d.category)||!diagnosticStatus(d.http_status)||!diagnosticVehicleErrors.includes(d.vehicle_error)||diagnosticFlags.some(key=>typeof d[key]!=='boolean'))return;
  if((d.request_written&&!d.http_initiated)||(d.response_received&&!d.http_initiated)||(d.http_initiated&&!d.reservation_acknowledged))return;
  if((d.exception_type==='none')!==(d.category==='none')||(d.exception_type==='none')!==(d.failure_stage==='none')||(d.vehicle_error!=='none'&&d.exception_type==='none'))return;
  if(['handshake','state_handshake'].includes(d.kind)&&d.authenticated_session_ready&&!d.response_received)return;
  // Session proof can carry from the preceding handshake into a command whose
  // own HTTP flags are reset. It need not imply a response for this wire attempt.
  result.diagnostic={...d};
 }
 if(Object.hasOwn(value,'local_transport')){
  const t=value.local_transport;
  if(!exactKeys(t,['stage','exception_type','http_status'])||!diagnosticStages.includes(t.stage)||!pythonExceptions.includes(t.exception_type)||!diagnosticStatus(t.http_status))return;
  result.local_transport={...t};
 }
 return result;
}
function checkSuccessDiagnostic(value){
 // Existing tool/read successes without signing evidence retain their behavior.
 if(!object(value)||!Object.hasOwn(value,'diagnostic'))return;
 if(!exactKeys(value,['diagnostic']))throw Error();
 const d=safeUpstreamDiagnostic({error_category:'upstream_tool',diagnostic:value.diagnostic})?.diagnostic;
 if(!d||d.stage!=='operation_succeeded'||d.failure_stage!=='none'||d.exception_type!=='none'||d.category!=='none'||d.vehicle_error!=='none'||d.checkpoint_persistence_failed||d.local_finalization_failed)throw Error();
 if(['handshake','state_handshake'].includes(d.kind)&&(!d.authenticated_session_ready||!d.reservation_acknowledged||!d.http_initiated||!d.request_written||!d.response_received||d.http_status!==200))throw Error();
 return d;
}
const failure=(id,modern=false,classification='configuration',status,exception,upstream)=>{
 const fixed=safeUpstreamDiagnostic(upstream)?.diagnostic;
 const outcome=fixed?.exception_type==='command_status_rejected'?'reported_failure':fixed?.http_initiated===false?'refused_before_vehicle_request':'unknown';
 const diagnostic={failure_class:classification,command_outcome:outcome,retry:false,...(classification==='status'&&Number.isInteger(status)&&status>=100&&status<=599?{upstream_status:status}:{}),...(['network','timeout'].includes(classification)&&exception?exceptionDiagnostic(exception):{}),...(classification==='upstream_tool'?safeUpstreamDiagnostic(upstream)??{}:{})};
 return reply({jsonrpc:'2.0',id,result:{...(modern?{resultType:'complete'}:{}),content:[{type:'text',text:JSON.stringify(diagnostic)}],structuredContent:diagnostic,isError:true}});
};
const credential=value=>typeof value==='string'&&value.length>=16&&value.length<=4096&&/^[!-~]+$/u.test(value);
function setup(env){
 const missing=[];
 if(env.IDENTITY_BOUNDARY!=='sites'||typeof env.OWNER_USER_ID!=='string'||!env.OWNER_USER_ID.trim())missing.push('verified_owner_identity');
 if(!credential(env.BROKER_GATEWAY_TOKEN))missing.push('private_mac_gateway_credential');
 if(['ACCESS_CLIENT_ID','ACCESS_CLIENT_SECRET'].some(k=>!credential(env[k])))missing.push('cloudflare_routing_credentials');
 return {typed_command_count:toolsFor(env).filter(t=>t.name.startsWith('prepare_')&&t.name!=='prepare_control').length,typed_commands:toolsFor(env).filter(t=>t.name.startsWith('prepare_')&&t.name!=='prepare_control').map(t=>({name:t.name,parameters:t.inputSchema.properties})),remote_owner_approval:env.REMOTE_OWNER_APPROVAL==='enabled'?'owner-browser-required':'disabled',gateway:'online',vehicle_connection:'not_verified',vehicle_commands:remoteMode(env)==='live'?'configured-live; vehicle readiness unverified':'disabled',missing_configuration:missing,
 next_steps:[
 missing.includes('verified_owner_identity')?'Configure the verified Site-scoped owner identity through Sites; never substitute an email or guessed ID.':'The Site-scoped owner identity is configured. Preserve the private audience and owner checks.',
 missing.includes('cloudflare_routing_credentials')?'Configure the existing dedicated Cloudflare service credentials through supported Site secret settings. Never paste them into chat.':'Cloudflare routing credentials are configured. Verify the existing protected tunnel without regenerating credentials.',
 missing.includes('private_mac_gateway_credential')?'Configure the dedicated gateway credential through supported Site secret settings; keep Tesla authorization on the Mac.':remoteMode(env)==='live'?'The dedicated Mac gateway credential is configured. A live command also requires matching execution modes and an expiring one-action grant on the Mac.':'The dedicated Mac gateway credential is configured. Keep it scoped to reads, previews and physically disabled SDK mock tools.',
 'Route only your configured BROKER_URL /mcp to loopback port 8765, with your own Access policy and validated origin authentication.',
 'Start the existing configured Mac broker and tunnel, then verify an allowed read through this installed plugin. A setup check does not verify the car.',
 'Reuse valid saved Tesla authorization; do not repeat consent or overwrite it. Check the existing read allowance before a live read, and obtain approval before any new paid allowance. Virtual-key pairing and live commands remain separate.']};
}
function number(value,min,max){if(typeof value!=='number'||!Number.isFinite(value)||value<min||value>max)throw Error();return value;}
function filtered(name,data,args,mode){
 if(name.startsWith('prepare_')||name==='execute_control')return filterRemote(name,data,args,mode);
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
  if(!object(output)||output.jsonrpc!=='2.0'||output.id!==message.id)throw Error();
  if(Object.hasOwn(output,'error')){
   if(Object.hasOwn(output,'result')||(!exactKeys(output.error,['code','message'])&&!exactKeys(output.error,['code','message','data']))||!Number.isSafeInteger(output.error.code)||typeof output.error.message!=='string')throw Error();
   return failure(message.id,modern,'upstream_tool');
  }
  if(typeof output.result?.isError!=='boolean'||!Array.isArray(output.result.content)||output.result.content.length!==1||output.result.content[0]?.type!=='text'||typeof output.result.content[0].text!=='string')throw Error();
  // A valid upstream refusal is distinct from a malformed MCP envelope. Never
  // parse or echo its raw error text; retain only schema-checked enum evidence.
  if(output.result.isError)return failure(message.id,modern,'upstream_tool',undefined,undefined,output.result.structuredContent);
  const structuredDiagnostic=checkSuccessDiagnostic(output.result.structuredContent);
  const data=parseStrictJSON(output.result.content[0].text);
  if(object(data)&&Object.hasOwn(data,'diagnostic')){
   const bodyDiagnostic=checkSuccessDiagnostic({diagnostic:data.diagnostic});
   if(structuredDiagnostic&&[...diagnosticBaseFields,...diagnosticFlags].some(key=>structuredDiagnostic[key]!==bodyDiagnostic[key]))throw Error();
  }
  stage='filter';
  const result=filtered(params.name,data,params.arguments,mode);
  if(result.approval_path){result.approval_url=publicOrigin(env)+result.approval_path;delete result.approval_path;}
  return reply({jsonrpc:'2.0',id:message.id,result:{...complete,content:[{type:'text',text:JSON.stringify(result)}],isError:false}});
 } catch(error){return failure(message.id,modern,signal.aborted||error?.name==='TimeoutError'?'timeout':stage,undefined,error);} // No body, header, URL, token or exception logging.
}
export default {fetch:(request,env)=>gateway(request,env)};
