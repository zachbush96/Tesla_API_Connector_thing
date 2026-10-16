// No vehicle data, secrets, user identity or external resources in this page.
const headers={
 'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff',
 'Referrer-Policy':'no-referrer',
 'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'",
};
const page=live=>`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connector · Tesla connection</title><meta name="description" content="Your private Connector Tesla connection and setup status.">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>
:root{color-scheme:light;--paper:#eff5fa;--ink:#172637;--navy:#203952;--blue:#356b96;--muted:#627387;--white:#fff;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink)}main{max-width:1000px;margin:auto;padding:42px 28px 64px}header{display:flex;align-items:center;justify-content:space-between;gap:16px;padding-bottom:42px}.brand{font-family:"Avenir Next",sans-serif;font-weight:650;letter-spacing:.04em}.private{font-size:13px;color:var(--muted)}h1{font-family:"Avenir Next",sans-serif;font-weight:600;font-size:clamp(36px,6vw,60px);line-height:1.08;letter-spacing:-.045em;margin:20px 0}h2{font-size:20px;letter-spacing:-.02em;margin:0 0 18px}p{line-height:1.65;color:var(--muted);max-width:54ch}.hero{max-width:700px;margin-bottom:36px}.badge{display:inline-flex;align-items:center;gap:9px;font-size:13px;background:#dde8f2;color:var(--navy);padding:8px 12px;border-radius:30px}.badge::before{content:"";height:7px;width:7px;border-radius:50%;background:var(--blue)}.grid{display:grid;grid-template-columns:1fr 1fr;gap:22px}.panel{background:var(--white);border:1px solid #d7e2eb;border-radius:18px;padding:28px}.row{display:flex;justify-content:space-between;gap:20px;border-top:1px solid #e5edf3;padding:16px 0;font-size:14px}.row strong{font-weight:550;text-align:right}.pending{color:var(--muted)}button{border:0;border-radius:9px;background:var(--navy);color:var(--white);padding:13px 18px;font:inherit;font-size:14px;cursor:pointer;margin-top:14px}button:hover{background:var(--blue)}button:disabled{opacity:.6;cursor:wait}button:focus-visible,a:focus-visible{outline:3px solid var(--blue);outline-offset:4px}.small{font-size:13px;line-height:1.6}.steps{margin:0;padding-left:22px}.steps li{padding:0 0 18px 7px;line-height:1.55;font-size:14px}.steps span{display:block;color:var(--muted);margin-top:4px}.note{margin-top:30px;font-size:14px}footer{margin-top:38px;color:var(--muted);font-size:12px}.check-result{min-height:44px;margin:16px 0 0}a{color:var(--blue)}@media(max-width:660px){main{padding:26px 20px 40px}header{padding-bottom:26px}.grid{grid-template-columns:1fr}.panel{padding:22px}.private{font-size:12px}}
</style></head><body><main>
<header><div class="brand">CONNECTOR / TESLA</div><div class="private">Private connection</div></header>
<section class="hero"><div class="badge">Connection setup</div><h1>Connect your own Tesla.<br>Keep control private.</h1>
<p>Your private gateway is online. Finish verifying Connector and your Mac, then use your own saved Tesla authorization for an allowed read. Signing in to this page does not verify your car connection.</p></section>
<div class="grid"><section class="panel" aria-labelledby="status-heading"><h2 id="status-heading">Connection status</h2>
<div class="row"><span>Private gateway</span><strong>Online</strong></div>
<div class="row"><span>Car connection</span><strong class="pending">Not verified</strong></div>
<div class="row"><span>Vehicle commands</span><strong class="pending">${live?'Configured; readiness unverified':'Disabled'}</strong></div>
<button id="check" type="button">Test plugin tools</button><p class="small">Tests discovery and setup instructions through your signed-in session. It doesn't contact your car.</p>
<p class="small check-result" id="result" role="status" aria-live="polite"></p><ol class="steps small" id="diagnostics"></ol></section>
<section class="panel" aria-labelledby="steps-heading"><h2 id="steps-heading">Finish connecting</h2><ol class="steps">
<li>Connect Connector's plugin.<span>In ChatGPT, open Plugins → Personal → Created by you → Tesla Connector, then choose Install or Connect.</span></li>
<li>Verify the private Mac connection.<span>Check your own secure tunnel and gateway configuration. Keep your Mac online when using Connector with the car.</span></li>
<li>Use the saved read authorization.<span>Preserve your valid Keychain authorization. Check the existing read allowance before a live read; a new paid allowance needs approval. Live commands need separate setup and approval.</span></li>
</ol></section></div>
<p class="note">This page never asks for Tesla credentials. Keep tokens, private keys and client secrets out of chat.</p>
<footer>Cabin temperature, battery, charging and approximate location are read tools. ${live?'Live controls require verified pairing, an exact approved action and current vehicle checks. A submitted command does not verify its physical effect.':'Remote controls are available as SDK simulations only. Live commands remain disabled pending private consent and pairing.'}</footer>
</main><script src="/page.js" defer></script></body></html>`;
const script=`const button=document.getElementById('check');const result=document.getElementById('result');const steps=document.getElementById('diagnostics');button.addEventListener('click',async()=>{button.disabled=true;result.textContent='Testing plugin tools…';steps.replaceChildren();try{async function rpc(method,params){const response=await fetch('/browser-discovery',{method:'POST',credentials:'same-origin',cache:'no-store',redirect:'error',signal:AbortSignal.timeout(10000),headers:{'Content-Type':'application/json',Accept:'application/json','mcp-protocol-version':'2026-07-28'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params:{...params,_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientInfo':{name:'connector-setup-page',version:'2'},'io.modelcontextprotocol/clientCapabilities':{}}}})});if(!response.ok)throw Error();const data=await response.json();if(!data.result||data.result.resultType!=='complete'||data.result.isError)throw Error();return data.result;}const discovery=await rpc('server/discover',{});if(discovery.resultType!=='complete'||!discovery.supportedVersions?.includes('2026-07-28')||!discovery.capabilities?.tools)throw Error();const listing=await rpc('tools/list',{});if(!Array.isArray(listing.tools)||listing.tools.length<8)throw Error();const response=await rpc('tools/call',{name:'check_setup',arguments:{}});const setup=JSON.parse(response.content[0].text);result.textContent='Plugin endpoint passed: the typed command tools are discoverable, and check_setup works. ChatGPT may need its plugin connection refreshed. Car connection remains unverified; live commands are disabled.';for(const text of setup.next_steps){const item=document.createElement('li');item.textContent=text;steps.append(item);}}catch{result.textContent='Plugin test did not pass. Refresh this page and try again. If ChatGPT still shows no actions, open this plugin under Plugins → Personal → Created by you and choose Connect if available, then start a fresh chat.';}finally{button.disabled=false;}});`;
const icon='<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#203952"/><path d="M18 17v30m28-30v30M18 32h28" stroke="#eff5fa" stroke-width="6"/></svg>';
export function pageResponse(request,env={}){
 const live=env.REMOTE_CONTROL_MODE==='live';
 const path=new URL(request.url).pathname;
 if(!['/','/page.js','/favicon.svg','/status'].includes(path))return null;
 if(!['GET','HEAD'].includes(request.method))return new Response(null,{status:405,headers:{...headers,Allow:'GET, HEAD'}});
 let body,type;
 if(path==='/'){body=page(live);type='text/html; charset=utf-8';}
 else if(path==='/page.js'){body=live?script.replace('Car connection remains unverified; live commands are disabled.','Car connection remains unverified; live controls require verified pairing, an exact approved action and current vehicle checks.'):script;type='text/javascript; charset=utf-8';}
 else if(path==='/favicon.svg'){body=icon;type='image/svg+xml';}
 else{
  const configured=env.IDENTITY_BOUNDARY==='sites'&&typeof env.OWNER_USER_ID==='string'&&!!env.OWNER_USER_ID.trim()&&
   ['BROKER_GATEWAY_TOKEN','ACCESS_CLIENT_ID','ACCESS_CLIENT_SECRET'].every(k=>typeof env[k]==='string'&&env[k].length>=16&&env[k].length<=4096&&/^[!-~]+$/u.test(env[k]));
  body=JSON.stringify({gateway:'online',setup_required:!configured,vehicle_connection:'not_verified',vehicle_commands:live?'configured-live; vehicle readiness unverified':'disabled'});type='application/json';
 }
 return new Response(request.method==='HEAD'?null:body,{headers:{...headers,'Content-Type':type}});
}
