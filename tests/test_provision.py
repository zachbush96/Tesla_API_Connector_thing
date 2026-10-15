import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tesla_connector.provision import generate_broker_keys
from tesla_connector.keychain import add_tesla_credentials
from tesla_connector.service import SafeError

class ProvisionTests(unittest.TestCase):
    def test_private_distinct_keys_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o700)
            paths=generate_broker_keys(directory)
            self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in paths))
            self.assertNotEqual(paths[0].read_text(),paths[1].read_text())
            with self.assertRaises(SafeError):generate_broker_keys(directory)
    def test_public_directory_or_symlink_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o755)
            with self.assertRaises(SafeError):generate_broker_keys(root)
            root.chmod(0o700);(root/'operator.token').symlink_to(root/'absent')
            with self.assertRaises(SafeError):generate_broker_keys(root)
    def test_invalid_entry_never_loads_framework(self):
        with patch('tesla_connector.keychain.C.CDLL') as load:
            for value in ('','bad value','x'*8001):
                with self.assertRaises(SafeError):add_tesla_credentials('synthetic',value)
            load.assert_not_called()
    @unittest.skipUnless(os.uname().sysname == 'Darwin', 'macOS framework check')
    def test_framework_dictionary_with_mocked_keychain_write(self):
        import ctypes as C
        from unittest.mock import Mock
        original=C.CDLL
        write=Mock(return_value=0)
        class SecurityProxy:
            def __init__(self):self.library=original('/System/Library/Frameworks/Security.framework/Security')
            def __getattr__(self,name):return getattr(self.library,name)
            SecItemAdd=write
        def load(path):
            return SecurityProxy() if '/Security.framework/' in path else original(path)
        with patch('tesla_connector.keychain.C.CDLL',side_effect=load):
            add_tesla_credentials('synthetic-client','synthetic-secret')
        write.assert_called_once()
        self.assertTrue(write.call_args.args[0])
    def test_distinct_gateway_key_without_replacement(self):
        from tesla_connector.provision import generate_gateway_key
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o700)
            file=generate_gateway_key(directory)
            self.assertEqual(file.stat().st_mode & 0o777,0o600)
            self.assertEqual(len(file.read_text()),64)
            with self.assertRaises(SafeError):generate_gateway_key(directory)
