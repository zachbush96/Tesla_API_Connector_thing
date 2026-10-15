"""Approved local credential preparation; never reports secret values."""
import os
from pathlib import Path
import secrets
import stat
from .service import SafeError


def validate_private_directory(path):
    root=Path(path)
    info=root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
        raise SafeError('Owned private directory required')
    return root


def generate_broker_keys(path):
    root=validate_private_directory(path)
    names=('operator.token','mcp.token')
    if any((root/name).exists() or (root/name).is_symlink() for name in names):
        raise SafeError('Existing broker credential; refusing replacement')
    created=[]
    try:
        for name in names:
            fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            created.append(root/name)
            os.fchmod(fd,0o600)
            with os.fdopen(fd,'w') as out:
                out.write(secrets.token_urlsafe(48))
                out.flush();os.fsync(out.fileno())
        directory=os.open(root,os.O_RDONLY)
        try:os.fsync(directory)
        finally:os.close(directory)
    except Exception:
        for file in created:file.unlink(missing_ok=True)
        raise SafeError('Local broker credential preparation failed') from None
    return tuple(root/name for name in names)


def generate_gateway_key(path):
    root=validate_private_directory(path)
    file=root/'gateway.token'
    if file.exists() or file.is_symlink():raise SafeError('Existing gateway credential; refusing replacement')
    try:
        fd=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'w') as output:
            output.write(secrets.token_urlsafe(48));output.flush();os.fsync(output.fileno())
        return file
    except Exception:raise SafeError('Gateway credential preparation failed') from None
