// Trusted nonsecret owner deployment settings; never derived from client headers.
export function brokerTarget(env={}){
 const value=new URL(env.BROKER_URL??'https://broker.example.invalid/mcp');
 if(value.protocol!=='https:'||value.username||value.password||value.pathname!=='/mcp'||value.search||value.hash||value.hostname.endsWith('.invalid'))throw Error('Configure owner broker URL');
 return value.href;
}
export function publicOrigin(env={}){
 const text=env.GATEWAY_PUBLIC_ORIGIN??'https://connector.example.invalid';
 const value=new URL(text);
 if(value.protocol!=='https:'||value.username||value.password||value.pathname!=='/'||value.search||value.hash||text!==value.origin)throw Error('Configure canonical gateway HTTPS origin');
 return value.origin;
}
