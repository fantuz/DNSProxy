"""Collect PE import dependencies from the compiler prefix and produce a portable ZIP."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import zipfile


MACHINES = {'amd64': 0x8664, 'arm64': 0xaa64}


def check_machine(path, architecture):
    """Reject mislabeled EXEs and mixed-architecture third-party DLLs."""
    with path.open('rb') as stream:
        dos = stream.read(64)
        if len(dos) != 64 or dos[:2] != b'MZ':
            raise ValueError(f'Invalid DOS/PE header: {path.name}')
        offset = struct.unpack_from('<I', dos, 60)[0]
        if offset < 64 or offset > path.stat().st_size - 26:
            raise ValueError(f'Invalid PE offset: {path.name}')
        stream.seek(offset)
        pe = stream.read(26)
    if pe[:4] != b'PE\0\0' or struct.unpack_from('<H', pe, 24)[0] != 0x20b:
        raise ValueError(f'Expected a PE32+ executable: {path.name}')
    machine = struct.unpack_from('<H', pe, 4)[0]
    if machine != MACHINES[architecture]:
        raise ValueError(f'{path.name}: expected {architecture}, found PE machine 0x{machine:04x}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--arch', choices=MACHINES, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    dest = args.directory.resolve()
    available = {p.name.lower(): p for p in (args.prefix/'bin').glob('*.dll')}
    system = Path(os.environ['SystemRoot'])/'System32'
    pending = [dest/'dnsp-modern.exe']
    seen = set()
    while pending:
        binary = pending.pop()
        check_machine(binary, args.arch)
        imports = subprocess.check_output(['objdump', '-p', str(binary)], text=True)
        for name in re.findall(r'DLL Name:\s*(\S+)', imports):
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            if key in ('msys-2.0.dll', 'cygwin1.dll'):
                raise RuntimeError(f'Non-native runtime dependency: {name}')
            if key in available:
                copied = dest/available[key].name
                shutil.copy2(available[key], copied)
                pending.append(copied)
            elif not key.startswith(('api-ms-win-', 'ext-ms-win-')) and not (system/name).is_file():
                raise RuntimeError(f'Missing runtime dependency: {name}')
    shutil.copy2(args.prefix/'etc/ssl/certs/ca-bundle.crt', dest/'ca-bundle.crt')
    shutil.copytree(args.prefix/'share/licenses', dest/'third-party-licenses', dirs_exist_ok=True)
    shutil.copy2(root/'LICENSE', dest/'LICENSE')
    shutil.copy2(root/'docs/WINDOWS.md', dest/'WINDOWS.md')
    shutil.copy2(root/'docs/BLOCKLISTS.md', dest/'BLOCKLISTS.md')
    shutil.copy2(root/'scripts/update-blocklist.py', dest/'update-blocklist.py')
    for name in ('Start-DNSProxy.ps1', 'Start-DNSProxy.cmd', 'Install-DNSProxyService.ps1', 'Uninstall-DNSProxyService.ps1', 'ServiceFiles.ps1', 'Set-DNSProxyService.ps1', 'Set-DNSProxyDns.ps1', 'DNSProxyDns.psm1', 'Setup-DNSProxy.ps1'):
        shutil.copy2(root/'packaging/windows'/name, dest/name)
    packages = subprocess.check_output(['pacman', '-Q'], text=True)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    version = (root/'VERSION').read_text().strip()
    target = 'x86-64 / UCRT64' if args.arch == 'amd64' else 'ARM64 / CLANGARM64'
    (dest/'BUILD-INFO.txt').write_text(
        f'DNSProxy {version}\nSource commit: {commit}\nTarget: native Windows {target}\n'
        'Build package versions (MSYS2):\n' + packages +
        '\nDependency source packages and build recipes:\n'
        'https://packages.msys2.org/\nhttps://repo.msys2.org/mingw/sources/\n'
        'https://github.com/msys2/MINGW-packages\n', encoding='utf-8')
    files = sorted(p for p in dest.rglob('*') if p.is_file() and p.name != 'SHA256SUMS')
    (dest/'SHA256SUMS').write_text(''.join(
        f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(dest).as_posix()}\n'
        for p in files), encoding='utf-8')
    archive = dest.parent/f'dnsp-modern-{version}-windows-{args.arch}-poc.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as package:
        for path in sorted(dest.rglob('*')):
            if path.is_file():
                package.write(path, path.relative_to(dest).as_posix())
    archive.with_suffix('.zip.sha256').write_text(
        f'{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n', encoding='utf-8')
    print(f'Packaged {archive} with {len(seen)} resolved imports')


if __name__ == '__main__':
    main()
