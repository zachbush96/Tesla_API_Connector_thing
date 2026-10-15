"""Human-facing local approval console. Not reachable through MCP or public HTTP."""
import json
import os
from .service import SafeError
from .storage import digest


class OperatorConsole:
    def __init__(self, ledger, owner, configured_target, vehicle_label='Configured vehicle'):
        if not isinstance(vehicle_label, str) or not 1 <= len(vehicle_label) <= 80 or any(ord(c) < 32 for c in vehicle_label):
            raise SafeError('Invalid vehicle label')
        self.ledger = ledger
        self.owner = owner
        self.target = configured_target
        self.label = vehicle_label

    def approve(self, intent, *, ui=None):
        intent.validated()
        if intent.principal != self.owner or intent.target != self.target:
            raise SafeError('Intent does not belong to the configured operator and vehicle')
        owns_ui = False
        if ui is None:
            try:
                ui = open('/dev/tty', 'r+')
                if not os.isatty(ui.fileno()):
                    raise SafeError('Human terminal required; no stdin approval')
                owns_ui = True
            except OSError:
                raise SafeError('Human terminal unavailable; approval denied') from None
        try:
            binding = intent.binding().hex()[:12]
            ui.write('Private operator review — do not record or redirect this view.\n')
            ui.write(f'Vehicle: {json.dumps(self.label, ensure_ascii=True)}; configured target fingerprint: {digest(self.target)[:12]}\n')
            ui.write('Action: ' + intent.command + '\n')
            payload = json.loads(intent.payload_json)
            if intent.command == 'navigation_request':
                ui.write('Destination: ' + json.dumps(payload['value']['android.intent.TEXT'], ensure_ascii=True) + '\n')
                ui.write('Share timestamp: ' + payload['timestamp_ms'] + '\n')
            else:
                ui.write(f"Driver and passenger target: {payload['driver_temp']} degrees Celsius\n")
            ui.write('Single use; expires in 60 seconds; no implicit wake or HVAC start.\n')
            ui.write(f'Type APPROVE {binding} to approve this exact request, or anything else to deny: ')
            ui.flush()
            answer = ui.readline(256)
            if answer.rstrip('\r\n') != 'APPROVE ' + binding:
                raise SafeError('Operator denied request')
            return self.ledger.approve(intent, ttl=60)  # Ticket stays internal, never printed.
        finally:
            if owns_ui:
                ui.close()
