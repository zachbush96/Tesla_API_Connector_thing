"""Create only fresh owner-private directories/capabilities; no Tesla requests."""
import argparse
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tesla_connector.provision import generate_broker_keys, generate_gateway_key

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', required=True, type=Path)
    parser.add_argument('--secrets-dir', required=True, type=Path)
    args = parser.parse_args()
    paths = [args.state_dir, args.secrets_dir]
    checkout = Path(__file__).resolve().parents[1]
    for path in paths:
        if not path.is_absolute() or path.exists() or path.is_symlink():
            parser.error('Use fresh absolute private directories')
        if path.resolve().is_relative_to(checkout):
            parser.error('Private directories must be outside the checkout')
    if any(a.resolve().is_relative_to(b.resolve()) for a, b in (paths, paths[::-1])):
        parser.error('Private directories must be distinct and not nested')
    os.umask(0o077)
    # Parents must already exist and belong to the owner; never create a path tree.
    for path in paths:
        path.mkdir(mode=0o700)
    generate_broker_keys(args.secrets_dir)
    generate_gateway_key(args.secrets_dir)
    print('Fresh private state and broker capabilities prepared; no Tesla operation.')

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError):
        raise SystemExit('Preparation refused; private details withheld')
