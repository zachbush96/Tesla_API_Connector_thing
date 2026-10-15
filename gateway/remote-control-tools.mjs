export const REMOTE_TOOLS=[
  {
    "name": "prepare_control",
    "description": "STAGED REMOTE MOCK: prepare an exact control proposal for the configured vehicle. No car call or wake; no Mac interaction. Owner authentication required. Does not establish human consent.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "action": {
          "type": "string",
          "enum": [
            "climate_start",
            "climate_stop",
            "set_temperature",
            "charge_start",
            "charge_stop",
            "set_charge_limit",
            "set_charging_amps",
            "charge_port_open",
            "charge_port_close",
            "navigation_send",
            "lock",
            "unlock",
            "front_trunk",
            "rear_trunk",
            "flash_lights",
            "honk_horn"
          ]
        },
        "parameters": {
          "type": "object",
          "properties": {
            "celsius": {
              "type": "number",
              "minimum": 15,
              "maximum": 28
            },
            "percent": {
              "type": "integer",
              "minimum": 50,
              "maximum": 100
            },
            "amps": {
              "type": "integer",
              "minimum": 1,
              "maximum": 48
            },
            "destination": {
              "type": "string",
              "minLength": 1,
              "maxLength": 300
            }
          },
          "additionalProperties": false
        }
      },
      "required": [
        "action",
        "parameters"
      ],
      "additionalProperties": false
    },
    "annotations": {
      "readOnlyHint": false,
      "destructiveHint": false,
      "idempotentHint": false,
      "openWorldHint": false
    }
  },
  {
    "name": "execute_control",
    "description": "STAGED REMOTE MOCK ONLY: consume one exact expiring operation ID. No physical execution, car request or spending. Invoke only for an explicitly owner-requested/confirmed action under host assistant policy. No approved/confirmed boolean accepted. Live execution disabled.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "operation_id": {
          "type": "string",
          "pattern": "^[a-f0-9]{32}$"
        }
      },
      "required": [
        "operation_id"
      ],
      "additionalProperties": false
    },
    "annotations": {
      "readOnlyHint": false,
      "destructiveHint": false,
      "idempotentHint": true,
      "openWorldHint": false
    }
  }
];
export const LIVE_REMOTE_TOOLS=REMOTE_TOOLS.map(tool=>({...tool,
 description:tool.name==='prepare_control'
  ?'LIVE CONTROL PREVIEW: bind an exact expiring control proposal for the configured vehicle. Preparing sends no vehicle request. Review the action and gross cost; owner authentication does not establish human consent.'
  :'LIVE VEHICLE CONTROL: consume one exact expiring proposal and a separately armed, expiring one-action grant on the Mac. May physically operate the car and incur gross Fleet API charges within that grant ceiling. Invoke only for the exact owner-requested or confirmed action. The Site and Mac execution modes must match before execution. Only horn, lights and opening the charge port require current Park evidence; other actions do not query Park or drive state. A submitted or accepted command does not verify its physical effect. No wake, retry or fallback; an uncertain result must not be retried.',
 annotations:{...tool.annotations,destructiveHint:tool.name==='execute_control',idempotentHint:tool.name!=='execute_control',openWorldHint:true}
}));
export const remoteMode=env=>env?.REMOTE_CONTROL_MODE==='live'?'live':'mock';
export const CONTROL_SPECS={
  "climate_start": {
    "command": "auto_conditioning_start",
    "scope": "vehicle_cmds",
    "fields": [],
    "effect": "Start climate preconditioning"
  },
  "climate_stop": {
    "command": "auto_conditioning_stop",
    "scope": "vehicle_cmds",
    "fields": [],
    "effect": "Stop climate preconditioning"
  },
  "set_temperature": {
    "command": "set_temps",
    "scope": "vehicle_cmds",
    "fields": [
      "celsius"
    ],
    "effect": "Set driver and passenger temperature"
  },
  "charge_start": {
    "command": "charge_start",
    "scope": "vehicle_charging_cmds",
    "fields": [],
    "effect": "Start charging"
  },
  "charge_stop": {
    "command": "charge_stop",
    "scope": "vehicle_charging_cmds",
    "fields": [],
    "effect": "Stop charging"
  },
  "set_charge_limit": {
    "command": "set_charge_limit",
    "scope": "vehicle_charging_cmds",
    "fields": [
      "percent"
    ],
    "effect": "Set charge percentage limit"
  },
  "set_charging_amps": {
    "command": "set_charging_amps",
    "scope": "vehicle_charging_cmds",
    "fields": [
      "amps"
    ],
    "effect": "Set charging current"
  },
  "charge_port_open": {
    "command": "charge_port_door_open",
    "scope": "vehicle_charging_cmds",
    "fields": [],
    "effect": "Open charge port"
  },
  "charge_port_close": {
    "command": "charge_port_door_close",
    "scope": "vehicle_charging_cmds",
    "fields": [],
    "effect": "Close charge port"
  },
  "navigation_send": {
    "command": "navigation_request",
    "scope": "vehicle_cmds",
    "fields": [
      "destination"
    ],
    "effect": "Send destination to navigation"
  },
  "lock": {
    "command": "door_lock",
    "scope": "vehicle_cmds",
    "fields": [],
    "effect": "Lock vehicle"
  },
  "unlock": {
    "command": "door_unlock",
    "scope": "vehicle_cmds",
    "fields": [],
    "effect": "Unlock vehicle"
  },
  "front_trunk": {
    "command": "actuate_trunk",
    "scope": "vehicle_cmds",
    "fields": [],
    "effect": "Actuate front trunk; do not assume powered closing"
  },
  "rear_trunk": {
    "command": "actuate_trunk",
    "scope": "vehicle_cmds",
    "fields": [],
    "effect": "Actuate rear trunk; direction depends on hardware/state"
  },
  "flash_lights": {
    "command": "flash_lights",
    "scope": "vehicle_cmds",
    "fields": [],
    "effect": "Briefly flash headlights"
  },
  "honk_horn": {
    "command": "honk_horn",
    "scope": "vehicle_cmds",
    "fields": [],
    "effect": "Sound horn"
  }
};

const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const exact=(o,keys)=>object(o)&&Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));
const finite=(x,a,b)=>typeof x==='number'&&Number.isFinite(x)&&x>=a&&x<=b;
export function validateRemote(name,args){
 if(name==='execute_control'){
  if(!exact(args,['operation_id'])||typeof args.operation_id!=='string'||!/^[a-f0-9]{32}$/u.test(args.operation_id))throw Error();
  return {remote_mock_validated:true,dry_run:true,executed:false};
 }
 if(name!=='prepare_control'||!exact(args,['action','parameters'])||typeof args.action!=='string'||!Object.hasOwn(CONTROL_SPECS,args.action))throw Error();
 const spec=CONTROL_SPECS[args.action],p=args.parameters;
 if(!exact(p,spec.fields))throw Error();
 if(args.action==='set_temperature'&&!finite(p.celsius,15,28))throw Error();
 if(args.action==='set_charge_limit'&&(!Number.isInteger(p.percent)||!finite(p.percent,50,100)))throw Error();
 if(args.action==='set_charging_amps'&&(!Number.isInteger(p.amps)||!finite(p.amps,1,48)))throw Error();
 if(args.action==='navigation_send'&&(typeof p.destination!=='string'||p.destination.length<1||p.destination.length>300||!p.destination.trim()||/[\x00-\x1f\x7f\uD800-\uDFFF]/u.test(p.destination)))throw Error();
 return {remote_mock_validated:true,dry_run:true,executed:false};
}
export function filterRemote(name,data,args,mode='mock'){
 if(!object(data))throw Error();
 if(name==='execute_control'){
  if(mode==='live'){
   const keys=['action','simulated','submitted','accepted','vehicle_execution_verified','execution_enabled','sdk_commit','fleet_network_requests','gross_reserved_microdollars','prerequisite_data_requests','prerequisite_gross_reserved_microdollars','total_gross_reserved_microdollars'];
   if(!exact(data,keys)||!Object.hasOwn(CONTROL_SPECS,data.action))throw Error();
   // Match the exact documented per-action path, not a broad cost range. Only
   // horn, lights and opening the charge port have a Park/data preflight. The
   // other signed actions use a fresh domain handshake plus command; navigation
   // uses one REST share. None adds a wake, retry or fallback request.
   const navigation=data.action==='navigation_send';
   const park=['honk_horn','flash_lights','charge_port_open'].includes(data.action);
   const requests=navigation?1:park?3:2;
   const dataRequests=park?1:0;
   if(data.simulated!==false||data.submitted!==true||data.accepted!==true||data.vehicle_execution_verified!==false||data.execution_enabled!==true||data.sdk_commit!=='49977a18fd68567501d59e16a6c9e4a8b9348544'||data.fleet_network_requests!==requests||data.gross_reserved_microdollars!==requests*1000||data.prerequisite_data_requests!==dataRequests||data.prerequisite_gross_reserved_microdollars!==dataRequests*2000||data.total_gross_reserved_microdollars!==requests*1000+dataRequests*2000)throw Error();
   return {...data};
  }
  if(data.simulated!==true||data.executed!==false||data.vehicle_execution_verified!==false||data.execution_enabled!==false||data.sdk_commit!=='49977a18fd68567501d59e16a6c9e4a8b9348544'||!Number.isInteger(data.synthetic_sdk_requests)||data.synthetic_sdk_requests<1||data.synthetic_sdk_requests>2||data.fleet_network_requests!==0||data.gross_reserved_microdollars!==0||!Object.hasOwn(CONTROL_SPECS,data.action))throw Error();
  return {action:data.action,simulated:true,executed:false,vehicle_execution_verified:false,execution_enabled:false,sdk_commit:data.sdk_commit,synthetic_sdk_requests:data.synthetic_sdk_requests,fleet_network_requests:0,gross_reserved_microdollars:0};
 }
 const spec=CONTROL_SPECS[args.action];
 if(name!=='prepare_control'||!spec||data.action!==args.action||data.command!==spec.command||data.required_scope!==spec.scope||typeof data.operation_id!=='string'||!/^[a-f0-9]{32}$/u.test(data.operation_id)||data.expires_in_seconds!==300||data.dry_run!==true||data.executed!==false||data.execution_enabled!==(mode==='live')||data.simulated!==(mode!=='live')||data.gross_reserved_microdollars!==0)throw Error();
 if(mode==='live'&&data.estimated_gross_reservation_microdollars!==(['lock','unlock','front_trunk','rear_trunk'].includes(args.action)?6000:5000))throw Error();
 let parameters={};
 if(args.action==='set_temperature'){if(!exact(data.parameters,['driver_temp','passenger_temp'])||data.parameters.driver_temp!==args.parameters.celsius||data.parameters.passenger_temp!==args.parameters.celsius)throw Error();parameters={driver_temp:args.parameters.celsius,passenger_temp:args.parameters.celsius};}
 else if(args.action==='set_charge_limit'){if(!exact(data.parameters,['percent'])||data.parameters.percent!==args.parameters.percent)throw Error();parameters={percent:args.parameters.percent};}
 else if(args.action==='set_charging_amps'){if(!exact(data.parameters,['charging_amps'])||data.parameters.charging_amps!==args.parameters.amps)throw Error();parameters={charging_amps:args.parameters.amps};}
 else if(args.action==='navigation_send'){if(!exact(data.parameters,['destination'])||data.parameters.destination!=='[redacted]')throw Error();parameters={destination:'[redacted]'};}
 else if(args.action==='front_trunk'||args.action==='rear_trunk'){const which=args.action==='front_trunk'?'front':'rear';if(!exact(data.parameters,['which_trunk'])||data.parameters.which_trunk!==which)throw Error();parameters={which_trunk:which};}
 else if(!exact(data.parameters,[]))throw Error();
 return {operation_id:data.operation_id,expires_in_seconds:300,action:data.action,effect:spec.effect,command:spec.command,parameters,required_scope:spec.scope,dry_run:true,simulated:mode!=='live',executed:false,execution_enabled:mode==='live',gross_reserved_microdollars:0,...(mode==='live'?{estimated_gross_reservation_microdollars:data.estimated_gross_reservation_microdollars}:{}),requires_exact_owner_confirmation:true};
}
// Native parsing handles JSON grammar; the second bounded traversal rejects
// duplicate decoded keys and excess nesting before returning that value.
export function parseStrictJSON(text){
 const parsed=JSON.parse(text);let i=0;
 const ws=()=>{while(/[ \t\r\n]/u.test(text[i]??'~'))i++;};
 const string=()=>{const start=i++;let escaped=false;while(i<text.length){const c=text[i++];if(escaped){escaped=false;continue;}if(c==='\\'){escaped=true;continue;}if(c==='"')return JSON.parse(text.slice(start,i));}throw Error();};
 const value=depth=>{if(depth>64)throw Error();ws();const c=text[i];
  if(c==='{'){i++;ws();const keys=new Set();if(text[i]==='}'){i++;return;}while(true){ws();if(text[i]!=='"')throw Error();const k=string();if(keys.has(k))throw Error();keys.add(k);ws();if(text[i++]!==':')throw Error();value(depth+1);ws();if(text[i]==='}'){i++;return;}if(text[i++]!==',')throw Error();}}
  else if(c==='['){i++;ws();if(text[i]===']'){i++;return;}while(true){value(depth+1);ws();if(text[i]===']'){i++;return;}if(text[i++]!==',')throw Error();}}
  else if(c==='"')string();else{const start=i;while(i<text.length&&!/[ \t\r\n,}\]]/u.test(text[i]))i++;if(i===start)throw Error();}
 };
 value(0);ws();if(i!==text.length)throw Error();return parsed;
}
