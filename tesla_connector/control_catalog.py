"""Fixed reviewed catalog and typed validation. No raw endpoint passthrough."""
import json,math,re
from pathlib import Path
from .service import SafeError
CATALOG=json.loads(Path(__file__).with_name('control-catalog.json').read_text())
def parameters(action,args):
 spec=CATALOG.get(action)
 if spec is None or type(args)is not dict or set(args)!=set(spec['properties']):raise SafeError('Typed command parameters refused')
 for key,s in spec['properties'].items():
  v=args[key];kind=s['type']
  if kind=='boolean':ok=type(v)is bool
  elif kind in ('integer','number'):ok=type(v)in ((int,) if kind=='integer' else (int,float)) and math.isfinite(v) and s.get('minimum',-1e100)<=v<=s.get('maximum',1e100)
  else:ok=type(v)is str and s.get('minLength',0)<=len(v)<=s.get('maxLength',300) and v.strip() and not any(ord(c)<32 or ord(c)==127 or 0xD800<=ord(c)<=0xDFFF for c in v) and ('pattern' not in s or re.fullmatch(s['pattern'],v))
  if not ok or ('enum'in s and v not in s['enum']):raise SafeError('Typed command parameters refused')
 if action=='add_charge_schedule' and not(args['start_enabled']or args['end_enabled']):raise SafeError('A charging schedule needs a start or end time')
 return dict(args)
def ceiling(action):
 s=CATALOG[action]
 return 5000 if s['requires_park'] else (1000 if s['domain']=='REST' else 2000)+(2000 if s['required_facts'] else 0)
def redacted(action,payload):
 return {k:('[redacted]' if k in CATALOG[action]['sensitive_parameters'] else v)for k,v in payload.items()}
def typed_tools():
 return [{'name':'prepare_'+a,'description':'PREPARE ONLY: '+s['effect']+'. No vehicle request or grant. '+('Conditional on fitted hardware/firmware; vehicle support is unverified.' if s['support']=='hardware_or_firmware_unverified' else '')+' Review and approve the exact command in the owner-only approval page before execute_control.','inputSchema':{'type':'object','properties':s['properties'],'required':list(s['properties']),'additionalProperties':False},'annotations':{'readOnlyHint':False,'destructiveHint':False,'idempotentHint':False,'openWorldHint':False}}for a,s in CATALOG.items()]
