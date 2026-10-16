// Complete Modules Worker entry. Deploy only behind a verified Sites identity boundary.
import {gateway} from './sites-gateway.mjs';
import {approval} from './approval.mjs';
import {pageResponse} from './page.mjs';
export default {async fetch(request,env={}){
 return pageResponse(request,env)??await approval(request,env,undefined,gateway)??gateway(request,env);
}};
