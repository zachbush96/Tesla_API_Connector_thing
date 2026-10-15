package restricted
// Legacy SDK behavior fixtures cover the original sixteen actions.
// TestPythonCanonicalBindingsAndCatalog separately validates all 43 schemas.
func legacyTestCatalog() map[string]spec {
 out:=map[string]spec{}
 for _,name:=range []string{"climate_start","climate_stop","set_temperature","charge_start","charge_stop","set_charge_limit","set_charging_amps","charge_port_open","charge_port_close","navigation_send","lock","unlock","front_trunk","rear_trunk","flash_lights","honk_horn"} {out[name]=catalog[name]}
 return out
}
