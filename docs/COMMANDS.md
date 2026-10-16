# Command support and verification limits

The fixed catalog has 43 actions. These are implemented schemas and routing rules, not a guarantee of support on a vehicle. The offline stdio demo exposes three reads and two previews. It does not execute the catalog. The Python reference workflow adds 43 typed prepare tools, prepare_control and execute_control after explicit composition; human approval is separate. The supplied gateway uses the matching 43-action catalog, filters current receipt/budget contracts and provides exact human review links. The included UI arms one operation without sending a vehicle command.

All actions remain unverified on a new owner installation. Historical temperature verification does not transfer to this export. A catalog support field does not mean verified vehicle execution.

| Action | Fleet command | Scope | Preconditions / support |
| --- | --- | --- | --- |
| climate_start | auto_conditioning_start | vehicle_cmds | standard authorization/signing; implemented_unverified |
| climate_stop | auto_conditioning_stop | vehicle_cmds | standard authorization/signing; implemented_unverified |
| set_temperature | set_temps | vehicle_cmds | standard authorization/signing; implemented_unverified |
| charge_start | charge_start | vehicle_charging_cmds | cable; implemented_unverified |
| charge_stop | charge_stop | vehicle_charging_cmds | standard authorization/signing; implemented_unverified |
| set_charge_limit | set_charge_limit | vehicle_charging_cmds | standard authorization/signing; implemented_unverified |
| set_charging_amps | set_charging_amps | vehicle_charging_cmds | standard authorization/signing; implemented_unverified |
| charge_port_open | charge_port_door_open | vehicle_charging_cmds | standard authorization/signing; fresh verified Park; implemented_unverified |
| charge_port_close | charge_port_door_close | vehicle_charging_cmds | motorized_port, cable_absent; implemented_unverified |
| navigation_send | navigation_request | vehicle_cmds | standard authorization/signing; implemented_unverified |
| lock | door_lock | vehicle_cmds | standard authorization/signing; implemented_unverified |
| unlock | door_unlock | vehicle_cmds | standard authorization/signing; implemented_unverified |
| front_trunk | actuate_trunk | vehicle_cmds | standard authorization/signing; implemented_unverified |
| rear_trunk | actuate_trunk | vehicle_cmds | standard authorization/signing; implemented_unverified |
| flash_lights | flash_lights | vehicle_cmds | standard authorization/signing; fresh verified Park; implemented_unverified |
| honk_horn | honk_horn | vehicle_cmds | standard authorization/signing; fresh verified Park; implemented_unverified |
| set_zone_temperatures | set_temps | vehicle_cmds | standard authorization/signing; implemented_unverified |
| adjust_volume | adjust_volume | vehicle_cmds | user_present, mobile_access; hardware_or_firmware_unverified |
| media_next_fav | media_next_fav | vehicle_cmds | standard authorization/signing; implemented_unverified |
| media_prev_fav | media_prev_fav | vehicle_cmds | standard authorization/signing; implemented_unverified |
| media_next_track | media_next_track | vehicle_cmds | standard authorization/signing; implemented_unverified |
| media_prev_track | media_prev_track | vehicle_cmds | standard authorization/signing; implemented_unverified |
| media_volume_down | media_volume_down | vehicle_cmds | standard authorization/signing; implemented_unverified |
| media_volume_up | media_volume_up | vehicle_cmds | standard authorization/signing; implemented_unverified |
| media_toggle_playback | media_toggle_playback | vehicle_cmds | standard authorization/signing; implemented_unverified |
| seat_heat | remote_seat_heater_request | vehicle_cmds | climate_active; hardware_or_firmware_unverified |
| seat_cool | remote_seat_cooler_request | vehicle_cmds | climate_active; hardware_or_firmware_unverified |
| seat_auto_climate | remote_auto_seat_climate_request | vehicle_cmds | climate_active; hardware_or_firmware_unverified |
| steering_wheel_heat | remote_steering_wheel_heater_request | vehicle_cmds | climate_active; hardware_or_firmware_unverified |
| bioweapon_mode | set_bioweapon_mode | vehicle_cmds | standard authorization/signing; hardware_or_firmware_unverified |
| cabin_overheat_protection | set_cabin_overheat_protection | vehicle_cmds | standard authorization/signing; hardware_or_firmware_unverified |
| climate_keeper_mode | set_climate_keeper_mode | vehicle_cmds | standard authorization/signing; hardware_or_firmware_unverified |
| cabin_overheat_temperature | set_cop_temp | vehicle_cmds | standard authorization/signing; hardware_or_firmware_unverified |
| preconditioning_max | set_preconditioning_max | vehicle_cmds | standard authorization/signing; hardware_or_firmware_unverified |
| charge_standard | charge_standard | vehicle_charging_cmds | standard authorization/signing; hardware_or_firmware_unverified |
| charge_max_range | charge_max_range | vehicle_charging_cmds | standard authorization/signing; hardware_or_firmware_unverified |
| add_charge_schedule | add_charge_schedule | vehicle_charging_cmds | standard authorization/signing; hardware_or_firmware_unverified |
| add_precondition_schedule | add_precondition_schedule | vehicle_cmds | standard authorization/signing; hardware_or_firmware_unverified |
| remove_charge_schedule | remove_charge_schedule | vehicle_charging_cmds | standard authorization/signing; hardware_or_firmware_unverified |
| remove_precondition_schedule | remove_precondition_schedule | vehicle_cmds | standard authorization/signing; hardware_or_firmware_unverified |
| windows_vent | window_control | vehicle_cmds | standard authorization/signing; hardware_or_firmware_unverified |
| windows_close | window_control | vehicle_cmds | standard authorization/signing; hardware_or_firmware_unverified |
| vehicle_name | set_vehicle_name | vehicle_cmds | standard authorization/signing; hardware_or_firmware_unverified |

Parameter bounds, payloads and redaction rules live in tesla_connector/control-catalog.json; the signer carries the same catalog. Temperature sets both zones (15–28°C) without implicitly starting HVAC. Navigation sends the exact private destination, redacted from model previews. Trunk actuation does not promise powered closing. Charging/charge-port actions have state/hardware requirements. Park checks are command-specific.

Excluded: remote driving/drive start, PIN/security resets, key management, purchases, erasure, software installation, automatic wake/retry, raw endpoint passthrough and verification polling. Native preview and automatic login/deployment jobs are not bundled; the completed browser review frontend is included.

The earlier CommandAdapter and broader staged/live adapters have different roles; StagedControlAdapter remains production-disabled. Importing a live class or installing the SDK does not activate it. Remote owner approval uses the included human UI after you provision a verified private owner identity boundary.

Offline tests cannot prove Tesla acceptance, pairing, current pricing, region compatibility, hardware fit or physical effects.
