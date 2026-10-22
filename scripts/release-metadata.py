#!/usr/bin/env python3
"""Validate a release tag/changelog or list checksum-verified upload assets."""
import hashlib
import json
from pathlib import Path
import re
import sys


def notes(tag, root=Path('.')):
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?', tag):
        raise ValueError('expected a vMAJOR.MINOR.PATCH tag (optional prerelease)')
    version = tag[1:]
    manifest = json.loads((root / '.claude-plugin/plugin.json').read_text(encoding='utf-8'))
    if manifest['version'] != version:
        raise ValueError('tag and plugin manifest versions differ')
    launcher = (root / 'bin/taintwatch-launcher').read_text(encoding='utf-8')
    if not re.search(r'^version=' + re.escape(version) + r'$', launcher, re.M):
        raise ValueError('tag and launcher versions differ')
    changelog = (root / 'CHANGELOG.md').read_text(encoding='utf-8')
    heading = re.search(r'^## \[' + re.escape(version) + r'\](?:[^\n]*)\n', changelog, re.M)
    if not heading:
        raise ValueError('CHANGELOG.md needs a section for [' + version + ']')
    rest = changelog[heading.end():]
    body = re.split(r'^## ', rest, maxsplit=1, flags=re.M)[0].strip()
    # Keep a Changelog link definitions are navigation, not release notes.
    body = re.sub(r'^\[[^\]]+\]:.*$', '', body, flags=re.M).strip()
    if not re.sub(r'(?m)^#+.*$', '', body).strip():
        raise ValueError('release changelog section is empty')
    return heading.group(0).strip() + '\n\n' + body + '\n'


def assets(dist, require_signature=True):
    """Only upload checksum-covered payloads and the signed checksum pair."""
    paths = []
    names = set()
    for line in (dist / 'checksums.txt').read_text(encoding='utf-8').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        if not match:
            raise ValueError('invalid checksum record')
        digest, name = match.groups()
        if name in names:
            raise ValueError('duplicate checksum filename')
        names.add(name)
        candidates = [p for p in dist.rglob(name) if p.is_file() and not p.is_symlink()]
        if len(candidates) != 1:
            raise ValueError('expected one asset for ' + name)
        path = candidates[0]
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('checksum mismatch for ' + name)
        paths.append(path)
    required = {'taintwatch-' + os + '-' + arch for os in ('linux', 'darwin') for arch in ('amd64', 'arm64')}
    if not required <= names:
        raise ValueError('missing raw launcher assets')
    if sum(name.endswith('.tar.gz') for name in names) != 4 or sum(name.endswith('.sbom.json') for name in names) != 4:
        raise ValueError('expected four archives and four SBOMs')
    metadata = ('checksums.txt', 'checksums.txt.sigstore.json') if require_signature else ('checksums.txt',)
    for name in metadata:
        path = dist / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
            raise ValueError('missing checksum/signature file: ' + name)
        paths.append(path)
    return sorted(paths)


def main():
    try:
        if len(sys.argv) == 3 and sys.argv[1] in ('--assets', '--check-snapshot'):
            print('\n'.join(str(p) for p in assets(Path(sys.argv[2]), sys.argv[1] == '--assets')))
        elif len(sys.argv) == 2:
            print(notes(sys.argv[1]), end='')
        else:
            raise ValueError('usage: release-metadata.py vVERSION | --assets dist | --check-snapshot dist')
    except (ValueError, OSError, KeyError) as error:
        print('release: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
