#!/usr/bin/env python3
"""Download and validate a DNSProxy list, then atomically replace one local file."""
import argparse
import hashlib
import os
from pathlib import Path
import ssl
import stat
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, HTTPSHandler, Request


def https_url(url):
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('Use an HTTPS URL without credentials or a fragment')
    return url


def identity(info):
    return None if info is None else (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                                      info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid)


class SecureRedirect(HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, request, response, code, message, headers, newurl):
        https_url(newurl)
        return super().redirect_request(request, response, code, message, headers, newurl)


def update(args):
    https_url(args.url)
    target = args.output.absolute()
    previous = target.lstat() if target.exists() or target.is_symlink() else None
    if previous and not stat.S_ISREG(previous.st_mode):
        raise ValueError('Output must be a regular file, not a symlink or directory')
    context = ssl.create_default_context(cafile=args.ca_file)
    opener = build_opener(SecureRedirect(), HTTPSHandler(context=context))
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix='.' + target.name + '.', delete=False) as output:
            temporary = Path(output.name)
            request = Request(args.url, headers={'Accept-Encoding': 'identity', 'User-Agent': 'DNSProxy-blocklist-updater'})
            size = 0
            digest = hashlib.sha256()
            deadline = time.monotonic() + 60
            with opener.open(request, timeout=15) as response:
                https_url(response.geturl())
                media = response.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
                if media not in ('text/plain', 'application/octet-stream', 'text/x-hosts'):
                    raise ValueError('Expected a plain-text domain/hosts list')
                if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
                    raise ValueError('Compressed responses are not accepted')
                while True:
                    if time.monotonic() > deadline:
                        raise TimeoutError('Download exceeded its time budget')
                    chunk = response.read(min(65536, args.max_bytes - size + 1))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > args.max_bytes:
                        raise ValueError('Download exceeds the configured byte limit')
                    digest.update(chunk)
                    output.write(chunk)
            if not size:
                raise ValueError('Downloaded list is empty')
            if args.sha256 and digest.hexdigest() != args.sha256.lower():
                raise ValueError('SHA256 mismatch')
            output.flush()
            os.fsync(output.fileno())
        validation = subprocess.run([str(args.binary), '--blocklist', str(temporary), '--check-blocklists'],
                                    text=True, capture_output=True, timeout=30)
        if validation.returncode:
            raise ValueError('List validation failed: ' + validation.stderr.strip())
        # A comment-only response is usually a broken feed; intentional empty
        # policy can still be installed explicitly by editing the local file.
        if 'blocklist_entries=0 ' in validation.stdout:
            raise ValueError('Downloaded list contains no domain rules')
        if os.name != 'nt' and previous:
            if os.geteuid() == 0:
                os.chown(temporary, previous.st_uid, previous.st_gid)
            elif previous.st_uid != os.geteuid():
                raise ValueError('Cannot preserve the existing file owner')
        os.chmod(temporary, stat.S_IMODE(previous.st_mode) & 0o666 if previous else 0o644)
        for attempt in range(6):
            try:
                # Check identity again: do not replace a file changed by another
                # updater/administrator while the download was underway.
                current = target.lstat() if target.exists() or target.is_symlink() else None
                if identity(current) != identity(previous):
                    raise ValueError('Output changed while downloading; retry the update')
                os.replace(temporary, target)
                temporary = None
                break
            except PermissionError:
                if os.name != 'nt' or attempt == 5:
                    raise
                time.sleep(0.1 * (attempt + 1))
        if os.name != 'nt':
            directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        print(f'Updated {target}: bytes={size} sha256={digest.hexdigest()}')
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url')
    parser.add_argument('output', type=Path)
    parser.add_argument('--binary', type=Path, default=Path('dnsp-modern'))
    parser.add_argument('--ca-file', help='Optional PEM CA bundle for the HTTPS feed')
    parser.add_argument('--sha256', help='Expected SHA256 digest, obtained separately')
    parser.add_argument('--max-bytes', type=int, default=64 * 1024 * 1024)
    args = parser.parse_args()
    if args.binary.is_file():
        args.binary = args.binary.resolve()
    if not 1 <= args.max_bytes <= 64 * 1024 * 1024:
        parser.error('--max-bytes must be between 1 and 67108864')
    if args.sha256 and (len(args.sha256) != 64 or any(c not in '0123456789abcdefABCDEF' for c in args.sha256)):
        parser.error('--sha256 requires 64 hexadecimal characters')
    try:
        update(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Blocklist update failed: {error}\n')


if __name__ == '__main__':
    main()
