"""Non-secret owner configuration. Configure before consent; exact HTTPS origin only."""
import os
from urllib.parse import urlsplit
PUBLIC_ORIGIN = os.environ.get('TESLA_CONNECTOR_PUBLIC_ORIGIN', 'https://connector.example.invalid')
_parts = urlsplit(PUBLIC_ORIGIN)
if (_parts.scheme != 'https' or not _parts.hostname or _parts.username or _parts.password
        or _parts.path or _parts.query or _parts.fragment or _parts.port not in (None, 443)):
    raise ValueError('Configure a canonical HTTPS public origin without a path')
