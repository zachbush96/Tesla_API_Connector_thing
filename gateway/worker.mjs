import {REMOTE_TOOLS,validateRemote,parseStrictJSON} from './remote-control-tools.mjs';
// Candidate Sites/Workers runtime adapter. MOCK ONLY; no fetch calls or credentials.
// Trust identity headers ONLY behind Sites' documented authentication boundary.
// Do not expose this directly as a generic Worker that accepts spoofed headers.
const annotations = read => ({readOnlyHint: read, destructiveHint: false, idempotentHint: true, openWorldHint: read});
const schema = properties => ({type: 'object', properties, required: Object.keys(properties), additionalProperties: false});
export const tools = [
  {name:'check_setup',description:'Check this gateway and return remaining setup steps. No Tesla requests or vehicle commands.',inputSchema:schema({}),annotations:annotations(true)},
  {name: 'read_battery_charging', description: 'READ: synthetic battery and charging only.', inputSchema: schema({}), annotations: annotations(true)},
  {name:'read_temperature',description:'READ: cabin temperature and vehicle timestamp only; synthetic until Mac live-read is approved. No HVAC change or wake.',inputSchema:schema({}),annotations:annotations(true)},
  {name: 'read_location', description: 'READ: synthetic coarse location only.', inputSchema: schema({}), annotations: annotations(true)},
  {name: 'preview_navigation', description: 'COMMAND PREVIEW ONLY; destination redacted; no execution.', inputSchema: schema({destination: {type:'string',minLength:1,maxLength:300}}), annotations: annotations(false)},
  {name: 'preview_temperature', description: 'COMMAND PREVIEW ONLY; both zones; no execution.', inputSchema: schema({celsius:{type:'number',minimum:15,maximum:28}}), annotations: annotations(false)},
].concat(REMOTE_TOOLS);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const json = (value, status=200) => new Response(JSON.stringify(value), {status, headers:{'Content-Type':'application/json', 'Cache-Control':'no-store'}});
function output(name, args) {
  if(REMOTE_TOOLS.some(t=>t.name===name))return validateRemote(name,args);
  const tool = tools.find(t => t.name === name);
  if (!tool || !object(args)) throw new Error();
  const keys = Object.keys(tool.inputSchema.properties);
  if (Object.keys(args).length !== keys.length || keys.some(k => !Object.hasOwn(args,k))) throw new Error();
  for (const key of keys) {
    const p = tool.inputSchema.properties[key];
    if (p.type === 'string') {
      if (typeof args[key] !== 'string' || Array.from(args[key]).length < p.minLength || Array.from(args[key]).length > p.maxLength || !args[key].trim() || /[\x00-\x1f\x7f]/u.test(args[key])) throw new Error();
    } else if (typeof args[key] !== 'number' || !Number.isFinite(args[key]) || args[key] < p.minimum || args[key] > p.maximum) throw new Error();
  }
  if (name === 'read_battery_charging') return {mode:'mock',battery_percent:72,charging_state:'Disconnected',charge_limit_percent:80,charger_power_kw:0};
  if (name === 'read_temperature') return {mode:'mock',inside_celsius:19,inside_fahrenheit:66.2,vehicle_timestamp_ms:1700000000000,synthetic:true};
  if (name === 'read_location') return {mode:'mock',latitude_approx:0,longitude_approx:0,synthetic:true,precision:'0.1 degree'};
  if (name === 'preview_navigation') return {dry_run:true,executed:false,command:'navigation_request',destination:'[redacted]',proxy_support:'official REST forwarding path; no execution'};
  if(name==='check_setup')return {gateway:'online',vehicle_connection:'not_verified',vehicle_commands:'disabled'};
  return {dry_run:true,executed:false,command:'set_temps',celsius:args.celsius};
}
export async function boundedBody(request) {
  const reader = request.body?.getReader();
  if (!reader) return '';
  const decoder = new TextDecoder('utf-8', {fatal:true});
  let length=0, text='';
  try {
    while (true) {
      const {done,value}=await reader.read();
      if (done) break;
      length += value.byteLength;
      // A cloned Request tees its body; awaiting cancellation can wait forever
      // for the unread sibling. Refuse immediately and handle cancellation errors.
      if (length > 65536) { void reader.cancel().catch(()=>{}); throw new RangeError(); }
      text += decoder.decode(value,{stream:true});
    }
    return text + decoder.decode();
  } finally { reader.releaseLock(); }
}
export async function handle(request, env={}) {
  const url = new URL(request.url);
  if (url.pathname !== '/mcp') return new Response(null,{status:404});
  if (request.method !== 'POST') return new Response(null,{status:405,headers:{Allow:'POST'}});
  const origin=request.headers.get('Origin');
  if (origin && origin !== (env.ALLOWED_ORIGIN??url.origin)) return new Response(null,{status:403});
  if (request.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase() !== 'application/json') return new Response(null,{status:415});
  if (!request.headers.get('Accept')?.includes('application/json')) return new Response(null,{status:406});
  let message;
  try { message=parseStrictJSON(await boundedBody(request)); }
  catch(error) { return error instanceof RangeError ? new Response(null,{status:413}) : json({jsonrpc:'2.0',id:null,error:{code:-32700,message:'Parse error'}},400); }
  if (!object(message) || message.jsonrpc !== '2.0' || typeof message.method !== 'string' ||
      (Object.hasOwn(message,'id') && (!['string','number'].includes(typeof message.id) || (typeof message.id === 'number' && !Number.isFinite(message.id))))) {
    return json({jsonrpc:'2.0',id:null,error:{code:-32600,message:'Invalid request'}},400);
  }
  const params=Object.hasOwn(message,'params') ? message.params : {};
  if (!object(params)) return json({jsonrpc:'2.0',id:message.id ?? null,error:{code:-32602,message:'Invalid parameters'}},400);
  // Static discovery and non-sensitive setup diagnostics must work before vehicle setup.
  // Sites still enforces this publication's private audience. No user identity is invented.
  const diagnostic=message.method==='tools/call'&&params.name==='check_setup';
  if(!['server/discover','initialize','tools/list','ping','notifications/initialized'].includes(message.method)&&!diagnostic){
    if(typeof env.OWNER_USER_ID!=='string'||!env.OWNER_USER_ID.trim()||env.IDENTITY_BOUNDARY!=='sites')return new Response(null,{status:503});
    const user=request.headers.get('oai-authenticated-user-id');
    if(!user)return new Response(null,{status:401});
    if(user!==env.OWNER_USER_ID)return new Response(null,{status:403});
  }
  if (!Object.hasOwn(message,'id')) return new Response(null,{status:202});
  let result;
  if (message.method==='server/discover') {
    result={resultType:'complete',supportedVersions:['2026-07-28','2025-11-25','2025-06-18','2024-11-05'],capabilities:{tools:{}},_meta:{'io.modelcontextprotocol/serverInfo':{name:'tesla-connector-remote-mock',version:'0.4.0'}}};
  } else if (message.method==='initialize') {
    const supported=['2025-11-25','2025-06-18','2024-11-05'];
    result={protocolVersion:supported.includes(params.protocolVersion)?params.protocolVersion:supported[0],capabilities:{tools:{}},serverInfo:{name:'tesla-connector-remote-mock',version:'0.3.0'}};
  } else if (message.method==='ping') result={};
  else if (message.method==='tools/list') result={tools};
  else if (message.method==='tools/call') {
    try {
      if (Object.keys(params).some(k => !['name','arguments','_meta'].includes(k))) throw new Error();
      result={content:[{type:'text',text:JSON.stringify(output(params.name,Object.hasOwn(params,'arguments') ? params.arguments : {}))}],isError:false};
    } catch { result={content:[{type:'text',text:'Tool or arguments rejected'}],isError:true}; }
  } else return json({jsonrpc:'2.0',id:message.id,error:{code:-32601,message:'Method not found'}});
  if(params._meta?.['io.modelcontextprotocol/protocolVersion']==='2026-07-28'||request.headers.get('mcp-protocol-version')==='2026-07-28')result.resultType='complete';
  return json({jsonrpc:'2.0',id:message.id,result});
}
export default {fetch:handle};
