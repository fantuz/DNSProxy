"""Collect PE import dependencies from the compiler prefix and produce a portable ZIP."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    dest = args.directory.resolve()
    available = {p.name.lower(): p for p in (args.prefix/'bin').glob('*.dll')}
    system = Path(os.environ['SystemRoot'])/'System32'
    pending = [dest/'dnsp-modern.exe']
    seen = set()
    while pending:
        binary = pending.pop()
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
    for name in ('Start-DNSProxy.ps1', 'Start-DNSProxy.cmd'):
        shutil.copy2(root/'packaging/windows'/name, dest/name)
    packages = subprocess.check_output(['pacman', '-Q'], text=True)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    version = (root/'VERSION').read_text().strip()
    (dest/'BUILD-INFO.txt').write_text(
        f'DNSProxy {version}\nSource commit: {commit}\nTarget: native Windows x86-64 / UCRT64\n'
        'Build package versions (MSYS2):\n' + packages +
        '\nDependency source packages and build recipes:\n'
        'https://packages.msys2.org/\nhttps://repo.msys2.org/mingw/sources/\n'
        'https://github.com/msys2/MINGW-packages\n', encoding='utf-8')
    files = sorted(p for p in dest.rglob('*') if p.is_file() and p.name != 'SHA256SUMS')
    (dest/'SHA256SUMS').write_text(''.join(
        f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(dest).as_posix()}\n'
        for p in files), encoding='utf-8')
    archive = dest.parent/f'dnsp-modern-{version}-windows-amd64-poc.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as package:
        for path in sorted(dest.rglob('*')):
            if path.is_file():
                package.write(path, path.relative_to(dest).as_posix())
    archive.with_suffix('.zip.sha256').write_text(
        f'{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n', encoding='utf-8')
    print(f'Packaged {archive} with {len(seen)} resolved imports')


if __name__ == '__main__':
    main()
