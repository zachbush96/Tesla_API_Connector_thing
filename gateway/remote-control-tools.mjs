export const CONTROL_CATALOG={
  "climate_start": {
    "command": "auto_conditioning_start",
    "scope": "vehicle_cmds",
    "effect": "Start climate preconditioning",
    "domain": "INFO",
    "properties": {},
    "requires_park": false,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "climate_stop": {
    "command": "auto_conditioning_stop",
    "scope": "vehicle_cmds",
    "effect": "Stop climate preconditioning",
    "domain": "INFO",
    "properties": {},
    "requires_park": false,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "set_temperature": {
    "command": "set_temps",
    "scope": "vehicle_cmds",
    "effect": "Set driver and passenger temperature",
    "domain": "INFO",
    "properties": {
      "celsius": {
        "type": "number",
        "minimum": 15,
        "maximum": 28
      }
    },
    "requires_park": false,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "charge_start": {
    "command": "charge_start",
    "scope": "vehicle_charging_cmds",
    "effect": "Start charging",
    "domain": "INFO",
    "properties": {},
    "requires_park": false,
    "required_facts": [
      "cable"
    ],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "charge_stop": {
    "command": "charge_stop",
    "scope": "vehicle_charging_cmds",
    "effect": "Stop charging",
    "domain": "INFO",
    "properties": {},
    "requires_park": false,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "set_charge_limit": {
    "command": "set_charge_limit",
    "scope": "vehicle_charging_cmds",
    "effect": "Set charge percentage limit",
    "domain": "INFO",
    "properties": {
      "percent": {
        "type": "integer",
        "minimum": 50,
        "maximum": 100
      }
    },
    "requires_park": false,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "set_charging_amps": {
    "command": "set_charging_amps",
    "scope": "vehicle_charging_cmds",
    "effect": "Set charging current",
    "domain": "INFO",
    "properties": {
      "amps": {
        "type": "integer",
        "minimum": 1,
        "maximum": 48
      }
    },
    "requires_park": false,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "charge_port_open": {
    "command": "charge_port_door_open",
    "scope": "vehicle_charging_cmds",
    "effect": "Open charge port",
    "domain": "INFO",
    "properties": {},
    "requires_park": true,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "charge_port_close": {
    "command": "charge_port_door_close",
    "scope": "vehicle_charging_cmds",
    "effect": "Close charge port",
    "domain": "INFO",
    "properties": {},
    "requires_park": false,
    "required_facts": [
      "motorized_port",
      "cable_absent"
    ],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "navigation_send": {
    "command": "navigation_request",
    "scope": "vehicle_cmds",
    "effect": "Send destination to navigation",
    "domain": "REST",
    "properties": {
      "destination": {
        "type": "string",
        "minLength": 1,
        "maxLength": 300,
        "description": ""
      }
    },
    "requires_park": false,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": [
      "destination"
    ]
  },
  "lock": {
    "command": "door_lock",
    "scope": "vehicle_cmds",
    "effect": "Lock vehicle",
    "domain": "SECURITY",
    "properties": {},
    "requires_park": false,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "unlock": {
    "command": "door_unlock",
    "scope": "vehicle_cmds",
    "effect": "Unlock vehicle",
    "domain": "SECURITY",
    "properties": {},
    "requires_park": false,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "front_trunk": {
    "command": "actuate_trunk",
    "scope": "vehicle_cmds",
    "effect": "Actuate front trunk; do not assume powered closing",
    "domain": "SECURITY",
    "properties": {},
    "requires_park": false,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "rear_trunk": {
    "command": "actuate_trunk",
    "scope": "vehicle_cmds",
    "effect": "Actuate rear trunk; direction depends on hardware/state",
    "domain": "SECURITY",
    "properties": {},
    "requires_park": false,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "flash_lights": {
    "command": "flash_lights",
    "scope": "vehicle_cmds",
    "effect": "Briefly flash headlights",
    "domain": "INFO",
    "properties": {},
    "requires_park": true,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "honk_horn": {
    "command": "honk_horn",
    "scope": "vehicle_cmds",
    "effect": "Sound horn",
    "domain": "INFO",
    "properties": {},
    "requires_park": true,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "set_zone_temperatures": {
    "command": "set_temps",
    "scope": "vehicle_cmds",
    "effect": "Set driver and passenger zones independently",
    "domain": "INFO",
    "properties": {
      "driver_temp": {
        "type": "number",
        "minimum": 15,
        "maximum": 28
      },
      "passenger_temp": {
        "type": "number",
        "minimum": 15,
        "maximum": 28
      }
    },
    "requires_park": false,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "adjust_volume": {
    "command": "adjust_volume",
    "scope": "vehicle_cmds",
    "effect": "Set media volume",
    "domain": "INFO",
    "properties": {
      "volume": {
        "type": "number",
        "minimum": 0,
        "maximum": 10
      }
    },
    "requires_park": false,
    "required_facts": [
      "user_present",
      "mobile_access"
    ],
    "support": "hardware_or_firmware_unverified",
    "sensitive_parameters": []
  },
  "media_next_fav": {
    "command": "media_next_fav",
    "scope": "vehicle_cmds",
    "effect": "Next favorite",
    "domain": "INFO",
    "properties": {},
    "requires_park": false,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "media_prev_fav": {
    "command": "media_prev_fav",
    "scope": "vehicle_cmds",
    "effect": "Previous favorite",
    "domain": "INFO",
    "properties": {},
    "requires_park": false,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "media_next_track": {
    "command": "media_next_track",
    "scope": "vehicle_cmds",
    "effect": "Next track",
    "domain": "INFO",
    "properties": {},
    "requires_park": false,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "media_prev_track": {
    "command": "media_prev_track",
    "scope": "vehicle_cmds",
    "effect": "Previous track",
    "domain": "INFO",
    "properties": {},
    "requires_park": false,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "media_volume_down": {
    "command": "media_volume_down",
    "scope": "vehicle_cmds",
    "effect": "Decrease volume one step",
    "domain": "INFO",
    "properties": {},
    "requires_park": false,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "media_volume_up": {
    "command": "media_volume_up",
    "scope": "vehicle_cmds",
    "effect": "Increase volume one step",
    "domain": "INFO",
    "properties": {},
    "requires_park": false,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "media_toggle_playback": {
    "command": "media_toggle_playback",
    "scope": "vehicle_cmds",
    "effect": "Toggle play/pause",
    "domain": "INFO",
    "properties": {},
    "requires_park": false,
    "required_facts": [],
    "support": "implemented_unverified",
    "sensitive_parameters": []
  },
  "seat_heat": {
    "command": "remote_seat_heater_request",
    "scope": "vehicle_cmds",
    "effect": "Set seat heat",
    "domain": "INFO",
    "properties": {
      "seat_position": {
        "type": "integer",
        "enum": [
          0,
          1,
          2,
          3,
          4,
          5,
          6,
          7,
          8
        ],
        "description": "0 driver; 1 passenger; 2 rear left; 3 rear left back; 4 rear center; 5 rear right; 6 rear right back; 7/8 third row left/right. Requires fitted heater."
      },
      "level": {
        "type": "integer",
        "enum": [
          0,
          1,
          2,
          3
        ],
        "description": "Off, low, medium, high"
      }
    },
    "requires_park": false,
    "required_facts": [
      "climate_active"
    ],
    "support": "hardware_or_firmware_unverified",
    "sensitive_parameters": []
  },
  "seat_cool": {
    "command": "remote_seat_cooler_request",
    "scope": "vehicle_cmds",
    "effect": "Set front seat cooling",
    "domain": "INFO",
    "properties": {
      "seat_position": {
        "type": "integer",
        "enum": [
          1,
          2
        ],
        "description": "1 front left; 2 front right, fitted ventilated seat required"
      },
      "seat_cooler_level": {
        "type": "integer",
        "enum": [
          1,
          2,
          3,
          4
        ],
        "description": "SDK converts to levels 0\u20133; 1 off through 4 high"
      }
    },
    "requires_park": false,
    "required_facts": [
      "climate_active"
    ],
    "support": "hardware_or_firmware_unverified",
    "sensitive_parameters": []
  },
  "seat_auto_climate": {
    "command": "remote_auto_seat_climate_request",
    "scope": "vehicle_cmds",
    "effect": "Enable or disable automatic front seat climate",
    "domain": "INFO",
    "properties": {
      "auto_seat_position": {
        "type": "integer",
        "enum": [
          1,
          2
        ],
        "description": "1 front left; 2 front right"
      },
      "auto_climate_on": {
        "type": "boolean"
      }
    },
    "requires_park": false,
    "required_facts": [
      "climate_active"
    ],
    "support": "hardware_or_firmware_unverified",
    "sensitive_parameters": []
  },
  "steering_wheel_heat": {
    "command": "remote_steering_wheel_heater_request",
    "scope": "vehicle_cmds",
    "effect": "Enable or disable steering wheel heat",
    "domain": "INFO",
    "properties": {
      "on": {
        "type": "boolean"
      }
    },
    "requires_park": false,
    "required_facts": [
      "climate_active"
    ],
    "support": "hardware_or_firmware_unverified",
    "sensitive_parameters": []
  },
  "bioweapon_mode": {
    "command": "set_bioweapon_mode",
    "scope": "vehicle_cmds",
    "effect": "Enable or disable Bioweapon Defense Mode if fitted",
    "domain": "INFO",
    "properties": {
      "on": {
        "type": "boolean"
      },
      "manual_override": {
        "type": "boolean"
      }
    },
    "requires_park": false,
    "required_facts": [],
    "support": "hardware_or_firmware_unverified",
    "sensitive_parameters": []
  },
  "cabin_overheat_protection": {
    "command": "set_cabin_overheat_protection",
    "scope": "vehicle_cmds",
    "effect": "Set cabin overheat protection",
    "domain": "INFO",
    "properties": {
      "on": {
        "type": "boolean"
      },
      "fan_only": {
        "type": "boolean"
      }
    },
    "requires_park": false,
    "required_facts": [],
    "support": "hardware_or_firmware_unverified",
    "sensitive_parameters": []
  },
  "climate_keeper_mode": {
    "command": "set_climate_keeper_mode",
    "scope": "vehicle_cmds",
    "effect": "Set climate keeper mode",
    "domain": "INFO",
    "properties": {
      "climate_keeper_mode": {
        "type": "integer",
        "enum": [
          0,
          1,
          2,
          3
        ],
        "description": "0 off; 1 Keep; 2 Dog; 3 Camp"
      },
      "manual_override": {
        "type": "boolean"
      }
    },
    "requires_park": false,
    "required_facts": [],
    "support": "hardware_or_firmware_unverified",
    "sensitive_parameters": []
  },
  "cabin_overheat_temperature": {
    "command": "set_cop_temp",
    "scope": "vehicle_cmds",
    "effect": "Set COP temperature level without activating COP",
    "domain": "INFO",
    "properties": {
      "cop_temp": {
        "type": "integer",
        "enum": [
          0,
          1,
          2
        ],
        "description": "Low 30\u00b0C/90\u00b0F; medium 35\u00b0C/95\u00b0F; high 40\u00b0C/100\u00b0F"
      }
    },
    "requires_park": false,
    "required_facts": [],
    "support": "hardware_or_firmware_unverified",
    "sensitive_parameters": []
  },
  "preconditioning_max": {
    "command": "set_preconditioning_max",
    "scope": "vehicle_cmds",
    "effect": "Set maximum preconditioning override",
    "domain": "INFO",
    "properties": {
      "on": {
        "type": "boolean"
      },
      "manual_override": {
        "type": "boolean"
      }
    },
    "requires_park": false,
    "required_facts": [],
    "support": "hardware_or_firmware_unverified",
    "sensitive_parameters": []
  },
  "charge_standard": {
    "command": "charge_standard",
    "scope": "vehicle_charging_cmds",
    "effect": "Set standard charge mode",
    "domain": "INFO",
    "properties": {},
    "requires_park": false,
    "required_facts": [],
    "support": "hardware_or_firmware_unverified",
    "sensitive_parameters": []
  },
  "charge_max_range": {
    "command": "charge_max_range",
    "scope": "vehicle_charging_cmds",
    "effect": "Set maximum range charge mode",
    "domain": "INFO",
    "properties": {},
    "requires_park": false,
    "required_facts": [],
    "support": "hardware_or_firmware_unverified",
    "sensitive_parameters": []
  },
  "add_charge_schedule": {
    "command": "add_charge_schedule",
    "scope": "vehicle_charging_cmds",
    "effect": "Add or modify a location-based charge schedule",
    "domain": "INFO",
    "properties": {
      "id": {
        "type": "integer",
        "minimum": 1,
        "maximum": 4294967295,
        "description": "Exact schedule ID; no automatic ID substitution"
      },
      "lat": {
        "type": "number",
        "minimum": -90,
        "maximum": 90
      },
      "lon": {
        "type": "number",
        "minimum": -180,
        "maximum": 180
      },
      "days_of_week": {
        "type": "string",
        "minLength": 1,
        "maxLength": 64,
        "description": "Comma-separated day names or ALL/WEEKDAYS",
        "pattern": "^(ALL|WEEKDAYS|(MON|TUES|WED|THURS|FRI|SAT|SUN)(,(MON|TUES|WED|THURS|FRI|SAT|SUN))*)$"
      },
      "enabled": {
        "type": "boolean"
      },
      "one_time": {
        "type": "boolean"
      },
      "start_time": {
        "type": "integer",
        "minimum": 0,
        "maximum": 1439,
        "description": "Vehicle local minutes after midnight"
      },
      "end_time": {
        "type": "integer",
        "minimum": 0,
        "maximum": 1439
      },
      "start_enabled": {
        "type": "boolean"
      },
      "end_enabled": {
        "type": "boolean"
      }
    },
    "requires_park": false,
    "required_facts": [],
    "support": "hardware_or_firmware_unverified",
    "sensitive_parameters": [
      "lat",
      "lon"
    ]
  },
  "add_precondition_schedule": {
    "command": "add_precondition_schedule",
    "scope": "vehicle_cmds",
    "effect": "Add or modify a location-based preconditioning schedule",
    "domain": "INFO",
    "properties": {
      "id": {
        "type": "integer",
        "minimum": 1,
        "maximum": 4294967295,
        "description": "Exact schedule ID; no automatic ID substitution"
      },
      "lat": {
        "type": "number",
        "minimum": -90,
        "maximum": 90
      },
      "lon": {
        "type": "number",
        "minimum": -180,
        "maximum": 180
      },
      "days_of_week": {
        "type": "string",
        "minLength": 1,
        "maxLength": 64,
        "description": "Comma-separated day names or ALL/WEEKDAYS",
        "pattern": "^(ALL|WEEKDAYS|(MON|TUES|WED|THURS|FRI|SAT|SUN)(,(MON|TUES|WED|THURS|FRI|SAT|SUN))*)$"
      },
      "enabled": {
        "type": "boolean"
      },
      "one_time": {
        "type": "boolean"
      },
      "precondition_time": {
        "type": "integer",
        "minimum": 0,
        "maximum": 1439,
        "description": "Vehicle local minutes after midnight"
      }
    },
    "requires_park": false,
    "required_facts": [],
    "support": "hardware_or_firmware_unverified",
    "sensitive_parameters": [
      "lat",
      "lon"
    ]
  },
  "remove_charge_schedule": {
    "command": "remove_charge_schedule",
    "scope": "vehicle_charging_cmds",
    "effect": "Remove exact charge schedule",
    "domain": "INFO",
    "properties": {
      "id": {
        "type": "integer",
        "minimum": 1,
        "maximum": 4294967295,
        "description": "Exact schedule ID; no automatic ID substitution"
      }
    },
    "requires_park": false,
    "required_facts": [],
    "support": "hardware_or_firmware_unverified",
    "sensitive_parameters": []
  },
  "remove_precondition_schedule": {
    "command": "remove_precondition_schedule",
    "scope": "vehicle_cmds",
    "effect": "Remove exact preconditioning schedule",
    "domain": "INFO",
    "properties": {
      "id": {
        "type": "integer",
        "minimum": 1,
        "maximum": 4294967295,
        "description": "Exact schedule ID; no automatic ID substitution"
      }
    },
    "requires_park": false,
    "required_facts": [],
    "support": "hardware_or_firmware_unverified",
    "sensitive_parameters": []
  },
  "windows_vent": {
    "command": "window_control",
    "scope": "vehicle_cmds",
    "effect": "Vent windows",
    "domain": "INFO",
    "properties": {},
    "requires_park": false,
    "required_facts": [],
    "support": "hardware_or_firmware_unverified",
    "sensitive_parameters": [],
    "fixed_payload": {
      "command": "vent"
    }
  },
  "windows_close": {
    "command": "window_control",
    "scope": "vehicle_cmds",
    "effect": "Close windows",
    "domain": "INFO",
    "properties": {},
    "requires_park": false,
    "required_facts": [],
    "support": "hardware_or_firmware_unverified",
    "sensitive_parameters": [],
    "fixed_payload": {
      "command": "close"
    }
  },
  "vehicle_name": {
    "command": "set_vehicle_name",
    "scope": "vehicle_cmds",
    "effect": "Rename the vehicle (not supported in Guest Mode)",
    "domain": "INFO",
    "properties": {
      "vehicle_name": {
        "type": "string",
        "minLength": 1,
        "maxLength": 64,
        "description": ""
      }
    },
    "requires_park": false,
    "required_facts": [],
    "support": "hardware_or_firmware_unverified",
    "sensitive_parameters": [
      "vehicle_name"
    ]
  }
};

const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const exact=(x,keys)=>object(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
const chars=s=>Array.from(s).length;
function validateParameters(action,args){
 const s=CONTROL_CATALOG[action];if(!s||!exact(args,Object.keys(s.properties)))throw Error();
 for(const [key,p]of Object.entries(s.properties)){const v=args[key];
  if(p.type==='boolean'){if(typeof v!=='boolean')throw Error();}
  else if(p.type==='number'||p.type==='integer'){if(typeof v!=='number'||!Number.isFinite(v)||(p.type==='integer'&&!Number.isSafeInteger(v))||v<p.minimum||v>p.maximum)throw Error();}
  else if(typeof v!=='string'||!v.trim()||chars(v)<p.minLength||chars(v)>p.maxLength||/[\x00-\x1f\x7f\ud800-\udfff]/u.test(Array.from(v).filter(c=>c.length===1).join(''))||(p.pattern&&!new RegExp(p.pattern,'u').test(v)))throw Error();
  if(p.enum&&!p.enum.includes(v))throw Error();
 }
 if(action==='add_charge_schedule'&&!args.start_enabled&&!args.end_enabled)throw Error();
 return args;
}
export function ceiling(action){const s=CONTROL_CATALOG[action];return s.requires_park?5000:(s.domain==='REST'?1000:2000)+(s.required_facts.length?2000:0);}
const schema=properties=>({type:'object',properties,required:Object.keys(properties),additionalProperties:false});
const typed=Object.entries(CONTROL_CATALOG).map(([a,s])=>({name:'prepare_'+a,description:'PREPARE ONLY: '+s.effect+'. No vehicle request. '+(s.support==='hardware_or_firmware_unverified'?'Requires supported hardware/firmware; not confirmed on this vehicle. ':'')+'Approve this exact proposal and spending ceiling in the owner-only approval page, then use execute_control.',inputSchema:schema(s.properties),annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:false,openWorldHint:false}}));
export const REMOTE_TOOLS=[{name:'prepare_control',description:'Prepare an exact reviewed allowlisted vehicle action. No execution or grant. Approve through the owner-only review page.',inputSchema:schema({action:{type:'string',enum:Object.keys(CONTROL_CATALOG)},parameters:{type:'object',description:'Use the matching typed prepare tool for the exact parameter schema.'}}),annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:false,openWorldHint:false}},{name:'execute_control',description:'Execute the exact owner-approved one-use proposal. In mock mode this simulates only. No retry or wake.',inputSchema:schema({operation_id:{type:'string',pattern:'^[a-f0-9]{32}$'}}),annotations:{readOnlyHint:false,destructiveHint:true,idempotentHint:false,openWorldHint:true}},...typed];
export const LIVE_REMOTE_TOOLS=REMOTE_TOOLS.map(t=>({...t,description:t.name==='execute_control'?'LIVE COMMAND: execute only the exact owner-requested action after the human owner approves its proposal in the linked review page. No model boolean or authentication alone can arm a grant. Successful INFO replies report vehicle application success; SECURITY reports command acknowledgement and navigation reports Fleet sharing success. These are distinct from independently read-back state. Any timeout or invalid response is unknown; never retry blindly.':t.description,annotations:{...t.annotations,openWorldHint:t.name==='execute_control'}}));
export const remoteMode=env=>env?.REMOTE_CONTROL_MODE==='live'?'live':'mock';
export const CONTROL_SPECS=Object.fromEntries(Object.entries(CONTROL_CATALOG).map(([a,s])=>[a,{command:s.command,scope:s.scope,fields:Object.keys(s.properties),effect:s.effect}]));
function decoded(name,args){if(name==='prepare_control'){if(!exact(args,['action','parameters']))throw Error();return {action:args.action,parameters:validateParameters(args.action,args.parameters)};}if(name.startsWith('prepare_')){const action=name.slice(8);return {action,parameters:validateParameters(action,args)};}throw Error();}
export function validateRemote(name,args){if(name==='execute_control'){if(!exact(args,['operation_id'])||typeof args.operation_id!=='string'||!/^[a-f0-9]{32}$/u.test(args.operation_id))throw Error();return {dry_run:true};}decoded(name,args);return {dry_run:true};}
function expectedParameters(a,p){if(a==='set_temperature')return {driver_temp:p.celsius,passenger_temp:p.celsius};if(a==='set_charging_amps')return {charging_amps:p.amps};if(a==='front_trunk'||a==='rear_trunk')return {which_trunk:a==='front_trunk'?'front':'rear'};if(a==='navigation_send')return {destination:'[redacted]'};const s=CONTROL_CATALOG[a];return Object.fromEntries(Object.entries({...p,...(s.fixed_payload??{})}).map(([k,v])=>[k,s.sensitive_parameters.includes(k)?'[redacted]':v]));}
export function filterRemote(name,data,args,mode){
 if(!object(data))throw Error();
 if(name==='execute_control'){
  const s=CONTROL_CATALOG[data.action];if(!s)throw Error();
  if(mode!=='live'){if(data.simulated!==true||data.executed!==false||data.execution_enabled!==false||data.vehicle_execution_verified!==false||data.fleet_network_requests!==0||data.gross_reserved_microdollars!==0||data.sdk_commit!=='49977a18fd68567501d59e16a6c9e4a8b9348544'||!Number.isInteger(data.synthetic_sdk_requests)||data.synthetic_sdk_requests<1||data.synthetic_sdk_requests>3)throw Error();return {action:data.action,simulated:true,executed:false,execution_enabled:false,vehicle_execution_verified:false,sdk_commit:data.sdk_commit,synthetic_sdk_requests:data.synthetic_sdk_requests,fleet_network_requests:0,gross_reserved_microdollars:0};}
  const n=s.domain==='REST'?1:s.requires_park?3:2,reads=s.requires_park||s.required_facts.length?1:0,evidence=s.domain==='REST'?'fleet_reported_success':s.domain==='SECURITY'?'vehicle_command_reported_success':'vehicle_application_reported_success';
  if(data.simulated!==false||data.submitted!==true||data.accepted!==true||data.execution_enabled!==true||data.vehicle_execution_verified!==false||data.resulting_state_verified!==false||data.success_evidence!==evidence||data.fleet_network_requests!==n||data.gross_reserved_microdollars!==n*1000||data.prerequisite_data_requests!==reads||data.prerequisite_gross_reserved_microdollars!==reads*2000||data.total_gross_reserved_microdollars!==ceiling(data.action)||data.sdk_commit!=='49977a18fd68567501d59e16a6c9e4a8b9348544')throw Error();
  return {action:data.action,simulated:false,submitted:true,accepted:true,success_evidence:evidence,resulting_state_verified:false,vehicle_execution_verified:false,execution_enabled:true,sdk_commit:data.sdk_commit,fleet_network_requests:n,gross_reserved_microdollars:n*1000,prerequisite_data_requests:reads,prerequisite_gross_reserved_microdollars:reads*2000,total_gross_reserved_microdollars:ceiling(data.action)};
 }
 const {action,parameters}=decoded(name,args),s=CONTROL_CATALOG[action],expected=expectedParameters(action,parameters);
 if(data.action!==action||data.command!==s.command||data.required_scope!==s.scope||typeof data.operation_id!=='string'||!/^[a-f0-9]{32}$/u.test(data.operation_id)||data.expires_in_seconds!==300||data.dry_run!==true||data.executed!==false||data.execution_enabled!==(mode==='live')||data.simulated!==(mode!=='live')||data.gross_reserved_microdollars!==0||!exact(data.parameters,Object.keys(expected))||Object.entries(expected).some(([k,v])=>data.parameters[k]!==v))throw Error();
 if(mode==='live'&&data.estimated_gross_reservation_microdollars!==ceiling(action))throw Error();
 return {operation_id:data.operation_id,expires_in_seconds:300,action,effect:s.effect,command:s.command,parameters:expected,required_scope:s.scope,dry_run:true,simulated:mode!=='live',executed:false,execution_enabled:mode==='live',gross_reserved_microdollars:0,...(mode==='live'?{estimated_gross_reservation_microdollars:ceiling(action)}:{}),requires_exact_owner_confirmation:true,...(mode==='live'?{approval_path:'/approve/'+data.operation_id}:{})};
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
