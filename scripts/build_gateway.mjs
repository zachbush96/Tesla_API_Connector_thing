// Dependency-free single-file ESM assembly. Creates only ignored build output.
import {readFile,mkdir,writeFile} from 'node:fs/promises';
const root=new URL('../',import.meta.url);
const read=name=>readFile(new URL('gateway/'+name,root),'utf8');
function once(text,from,to){
 if(text.split(from).length!==2)throw Error('Source contract changed: review build assembly');
 return text.replace(from,to);
}
let config=await read('config.mjs');
config=config.replaceAll('export function ','function ');
const block=(name,body,returned)=>'const '+name+'=(()=>{\n'+body+'\nreturn '+returned+';\n})();\n';
let remote=await read('remote-control-tools.mjs');
remote=remote.replaceAll('export const ','const ').replaceAll('export function ','function ');
let validation=await read('worker.mjs');
validation=once(validation,"import {REMOTE_TOOLS,validateRemote,parseStrictJSON} from './remote-control-tools.mjs';",'const {REMOTE_TOOLS,validateRemote,parseStrictJSON}=remote;');
validation=validation.replace('export const tools =','const tools =').replace('export async function boundedBody','async function boundedBody').replace('export async function handle','async function handle').replace('export default {fetch:handle};','');
let gateway=await read('sites-gateway.mjs');
gateway=once(gateway,"import {handle as validate, tools as mockTools, boundedBody} from './worker.mjs';",'const {handle:validate,tools:mockTools,boundedBody}=validation;');
gateway=once(gateway,"import {filterRemote,parseStrictJSON,LIVE_REMOTE_TOOLS,remoteMode} from './remote-control-tools.mjs';",'const {filterRemote,parseStrictJSON,LIVE_REMOTE_TOOLS,remoteMode}=remote;');
gateway=once(gateway,"import {brokerTarget,publicOrigin} from './config.mjs';",'const {brokerTarget,publicOrigin}=config;');
gateway=gateway.replace('export async function gateway','async function gateway').replace('export default {fetch:(request,env)=>gateway(request,env)};','');
let approval=await read('approval.mjs');
approval=once(approval,"import {parseStrictJSON} from './remote-control-tools.mjs';",'const {parseStrictJSON}=remote;');
approval=once(approval,"import {brokerTarget,publicOrigin} from './config.mjs';",'const {brokerTarget,publicOrigin}=config;');
approval=approval.replace('export async function approval','async function approval');
let page=await read('page.mjs');page=page.replace('export function pageResponse','function pageResponse');
const output=block('config',config,'{brokerTarget,publicOrigin}')+
 block('remote',remote,'{REMOTE_TOOLS,LIVE_REMOTE_TOOLS,remoteMode,validateRemote,filterRemote,parseStrictJSON}')+
 block('validation',validation,'{handle,tools,boundedBody}')+block('entry',gateway,'gateway')+
 block('ownerApproval',approval,'approval')+block('browser',page,'pageResponse')+
 'export default {async fetch(request,env){return browser(request,env)??await ownerApproval(request,env,undefined,entry)??entry(request,env)}};\n';
await mkdir(new URL('dist/',root),{recursive:true});
await writeFile(new URL('dist/gateway.mjs',root),output);
console.log('Built dist/gateway.mjs; no deployment or network performed');
