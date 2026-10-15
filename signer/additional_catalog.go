package restricted
import (
 _ "embed"
 "encoding/json"
 "math"
 "regexp"
 "unicode/utf8"
 um "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
)
//go:embed control-catalog.json
var catalogJSON []byte
type catalogEntry struct {Command string `json:"command"`;Scope string `json:"scope"`;Domain string `json:"domain"`;Properties map[string]map[string]any `json:"properties"`;Fixed map[string]any `json:"fixed_payload"`;Required []string `json:"required_facts"`}
var additionalCatalog=map[string]catalogEntry{}
func init(){
 if json.Unmarshal(catalogJSON,&additionalCatalog)!=nil {panic("fixed catalog invalid")}
 for a,e:=range additionalCatalog {if _,ok:=catalog[a];!ok {domain:=um.Domain_DOMAIN_INFOTAINMENT;if e.Domain=="SECURITY"{domain=um.Domain_DOMAIN_VEHICLE_SECURITY};catalog[a]=spec{e.Command,e.Scope,domain,false}}}
}
func additionalPayload(action string,p map[string]any)bool {
 e,ok:=additionalCatalog[action];if !ok||len(p)!=len(e.Properties)+len(e.Fixed){return false}
 for k,v:=range e.Fixed {if p[k]!=v{return false}}
 for k,s:=range e.Properties {v,ok:=p[k];if !ok{return false};kind,_:=s["type"].(string)
  switch kind {
  case "number","integer":n,ok:=v.(float64);if !ok||math.IsNaN(n)||math.IsInf(n,0){return false};if min,ok:=s["minimum"].(float64);ok&&n<min{return false};if max,ok:=s["maximum"].(float64);ok&&n>max{return false};if kind=="integer"&&n!=math.Trunc(n){return false}
  case "boolean":if _,ok:=v.(bool);!ok{return false}
  case "string":text,ok:=v.(string);if !ok||!utf8.ValidString(text)||hasControl(text){return false};n:=float64(utf8.RuneCountInString(text));if min,ok:=s["minLength"].(float64);ok&&n<min{return false};if max,ok:=s["maxLength"].(float64);ok&&n>max{return false};if pattern,ok:=s["pattern"].(string);ok&&!regexp.MustCompile(pattern).MatchString(text){return false}
  default:return false
  }
  if choices,ok:=s["enum"].([]any);ok{found:=false;for _,choice:=range choices{if choice==v{found=true}};if !found{return false}}
 }
 if action=="add_charge_schedule"&&p["start_enabled"]!=true&&p["end_enabled"]!=true{return false}
 return true
}
func requiredCatalogFacts(action string,f Facts)bool {
 for _,required:=range additionalCatalog[action].Required {switch required{
 case "cable":if !f.Cable{return false}
 case "cable_absent":if !f.CableAbsent{return false}
 case "motorized_port":if !f.MotorizedPort{return false}
 case "climate_active":if !f.ClimateActive{return false}
 case "user_present":if !f.UserPresent{return false}
 case "mobile_access":if !f.MobileAccess{return false}
 default:return false
 }}
 return true
}
