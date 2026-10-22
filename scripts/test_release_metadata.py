import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('release_metadata', Path(__file__).with_name('release-metadata.py'))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseNotesTest(unittest.TestCase):
    def test_changelog_contract(self):
        cases = [
            ('v0.1.0', '## [0.1.0] - 2026-10-22\n### Added\n- Guardrails.\n## [0.0.9]\nOld', True),
            ('v0.1.0', '## [Unreleased]\n- Pending', False),
            ('v0.1.0', '## [0.1.0]\n### Added\n', False),
            ('v0.2.0', '## [0.2.0]\n- Changed', False),
            ('v0.1.0;echo bad', '## [0.1.0]\n- Changed', False),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / '.claude-plugin').mkdir()
            (root / '.claude-plugin/plugin.json').write_text('{"version":"0.1.0"}')
            (root / 'bin').mkdir()
            (root / 'bin/taintwatch-launcher').write_text('version=0.1.0\n')
            for tag, changelog, valid in cases:
                with self.subTest(tag=tag, changelog=changelog):
                    (root / 'CHANGELOG.md').write_text(changelog)
                    if valid:
                        result = release.notes(tag, root)
                        self.assertIn('Guardrails.', result)
                        self.assertNotIn('Old', result)
                    else:
                        with self.assertRaises(ValueError):
                            release.notes(tag, root)
            (root / 'bin/taintwatch-launcher').write_text('version=0.0.9\n')
            with self.assertRaisesRegex(ValueError, 'launcher'):
                release.notes('v0.1.0', root)

    def test_assets_reject_malformed_or_mismatched_checksum(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            (dist / 'checksums.txt').write_text('not a checksum\n')
            with self.assertRaisesRegex(ValueError, 'invalid checksum'):
                release.assets(dist)
            (dist / 'taintwatch-linux-amd64').write_bytes(b'tampered')
            (dist / 'checksums.txt').write_text('0' * 64 + '  taintwatch-linux-amd64\n')
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                release.assets(dist)


    def test_complete_assets_and_required_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            records = []
            for os in ('linux', 'darwin'):
                for arch in ('amd64', 'arm64'):
                    for name in ('taintwatch-' + os + '-' + arch,
                                 'taintwatch_1.0.0_' + os + '_' + arch + '.tar.gz',
                                 'taintwatch_1.0.0_' + os + '_' + arch + '.tar.gz.sbom.json'):
                        data = ('test-only:' + name).encode()
                        (dist / name).write_bytes(data)
                        records.append(hashlib.sha256(data).hexdigest() + '  ' + name)
            (dist / 'checksums.txt').write_text('\n'.join(records) + '\n')
            self.assertEqual(len(release.assets(dist, require_signature=False)), 13)
            with self.assertRaisesRegex(ValueError, 'signature'):
                release.assets(dist)
            # Existence only is checked here; workflow cosign verifies its identity.
            (dist / 'checksums.txt.sigstore.json').write_text('test-only-bundle')
            self.assertEqual(len(release.assets(dist)), 14)


if __name__ == '__main__':
    unittest.main()
