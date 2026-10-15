#!/usr/bin/env python3
"""Owner-run local entry only: never reads the Tesla dashboard or uses clipboard."""
import getpass
import warnings
import os
import sys
from tesla_connector.keychain import add_tesla_credentials


def main():
    # Refuse piped input/fallback echo: actual owner terminal is required.
    with open('/dev/tty','w') as tty:
        if not os.isatty(tty.fileno()):raise ValueError()
        tty.write('Enter the approved Tesla app credentials locally. Values remain hidden.\n')
        tty.flush()
        with warnings.catch_warnings():
            warnings.simplefilter('error',getpass.GetPassWarning)
            client_id=getpass.getpass('Tesla Client ID (hidden): ',stream=tty)
            client_secret=getpass.getpass('Tesla Client Secret (hidden): ',stream=tty)
        for value in (client_id,client_secret):
            if not value or len(value)>8000 or not value.isascii() or any(c.isspace() for c in value):raise ValueError()
        add_tesla_credentials(client_id,client_secret)
        tty.write('Stored in the local non-synchronizing Keychain. No OAuth grant or vehicle action performed.\n')
        tty.flush()

if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt):
        sys.exit('Credential entry failed or cancelled; details withheld. Existing entries are never overwritten.')
