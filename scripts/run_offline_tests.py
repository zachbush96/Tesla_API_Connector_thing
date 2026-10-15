"""Run synthetic Python unit coverage with outbound socket connections denied."""
from pathlib import Path
import socket
import sys
import unittest
root = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(root), str(root / 'tests')]
def denied(*args, **kwargs):
    raise AssertionError('Network is forbidden in offline unit tests')
socket.socket.connect = denied
socket.create_connection = denied
suite = unittest.defaultTestLoader.discover(str(root / 'tests'))
result = unittest.TextTestRunner(verbosity=1).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
