"""Offline installer contract: platforms, versions, integrity and source fallback."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT.name
PREFIX = TOOL.upper()
IS_GO = (ROOT / 'go.mod').exists()

CURL = r'''#!/bin/bash
printf '%s\n' "$@" >>"$CURL_LOG"
out=''
url=''
while [ "$#" -gt 0 ]; do
 if [ "$1" = --output ]; then out="$2"; shift; fi
 url="$1"; shift
done
case "$url" in
 */releases/latest)
  [ "${FAIL_LATEST:-0}" = 1 ] && exit 22
  printf 'https://github.com/ilvar/%s/releases/tag/%s' "$TOOL" "${MOCK_TAG:-v9.8.7}" ;;
 *.sha256)
  hash=$(/usr/bin/sha256sum "$PAYLOAD") || exit 1
  hash="${hash%% *}"
  [ "${BAD_CHECKSUM:-0}" = 1 ] && hash=$(printf '%064d' 0)
  name="${url##*/}"; name="${name%.sha256}"
  printf '%s  %s\n' "$hash" "$name" >"$out" ;;
 *)
  [ "${FAIL_DOWNLOAD:-0}" = 1 ] && exit 22
  /usr/bin/cp "$PAYLOAD" "$out" || exit 1 ;;
esac
'''
CARGO = r'''#!/bin/bash
[ "$1" = --version ] && { printf 'cargo fixture\n'; exit 0; }
printf '%s\n' "$@" >>"$BUILD_LOG"
[ "${FAIL_BUILD:-0}" = 1 ] && exit 1
while [ "$#" -gt 0 ]; do
 if [ "$1" = --root ]; then
  /usr/bin/mkdir -p "$2/bin" || exit 1
  /usr/bin/cp "$PAYLOAD" "$2/bin/$TOOL" || exit 1
  exit 0
 fi
 shift
done
exit 1
'''
GO = r'''#!/bin/bash
[ "$1" = version ] && { printf 'go fixture\n'; exit 0; }
printf '%s\n' "$GOTOOLCHAIN" "$@" >>"$BUILD_LOG"
[ "${FAIL_BUILD:-0}" = 1 ] && exit 1
/usr/bin/mkdir -p "$GOBIN" || exit 1
/usr/bin/cp "$PAYLOAD" "$GOBIN/$TOOL" || exit 1
'''
RUSTUP = r'''#!/bin/bash
[ "${FAIL_COMPILER:-0}" = 1 ] && exit 1
[ "$1" = --version ] && { printf 'rustup fixture\n'; exit 0; }
printf '%s\n' "$@" >>"$COMPILER_LOG"
'''

class Installer(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'commands'
        self.dest = self.root / 'install with spaces'
        self.scratch = self.root / 'scratch'
        for p in [self.bin, self.dest, self.scratch]:
            p.mkdir()
        self.payload = self.root / 'payload'
        self.payload.write_text('#!/bin/bash\nprintf "fixture binary\\n"\n')
        self.stub('uname', '#!/bin/bash\ncase "$1" in -s) printf "%s" "$MOCK_OS";; -m) printf "%s" "$MOCK_ARCH";; *) exit 1;; esac\n')
        for name, content in [('curl', CURL), ('cargo', CARGO), ('go', GO), ('rustup', RUSTUP)]:
            self.stub(name, content)
        self.stub('sha256sum', '#!/bin/bash\nif [ "$1" = --version ] && [ "${FORCE_SHASUM:-0}" = 1 ]; then exit 127; fi\nexec /usr/bin/sha256sum "$@"\n')

    def stub(self, name, content):
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o755)

    def log(self, name):
        path = self.root / (name + '.log')
        return path.read_text() if path.exists() else ''

    def run_install(self, os_name='Linux', arch='x86_64', **extra):
        env = os.environ.copy()
        for key in list(env):
            if key.startswith(PREFIX + '_'):
                del env[key]
        env.update(PATH=f'{self.bin}:/usr/bin:/bin', HOME=str(self.root), TMPDIR=str(self.scratch),
                   MOCK_OS=os_name, MOCK_ARCH=arch, TOOL=TOOL, PAYLOAD=str(self.payload),
                   CURL_LOG=str(self.root/'curl.log'), BUILD_LOG=str(self.root/'build.log'),
                   COMPILER_LOG=str(self.root/'compiler.log'))
        env[PREFIX + '_INSTALL_DIR'] = str(self.dest)
        env.update(extra)
        result = subprocess.run(['/bin/bash', str(ROOT/'install.sh')], env=env, capture_output=True, text=True)
        self.assertEqual(list(self.scratch.iterdir()), [], 'temporary files leaked')
        return result

    def installed(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.dest/TOOL).read_bytes(), self.payload.read_bytes())
        self.assertTrue(os.access(self.dest/TOOL, os.X_OK))

    def test_all_platforms_download_checksums_without_building(self):
        for os_name, arch, rust_target, go_target in [
            ('Linux','x86_64','x86_64-unknown-linux-musl','linux-amd64'),
            ('Linux','arm64','aarch64-unknown-linux-musl','linux-arm64'),
            ('Darwin','x86_64','x86_64-apple-darwin','darwin-amd64'),
            ('Darwin','arm64','aarch64-apple-darwin','darwin-arm64'),
        ]:
            with self.subTest(os=os_name,arch=arch):
                self.installed(self.run_install(os_name, arch))
                asset = TOOL + '-' + (go_target if IS_GO else rust_target)
                self.assertIn('/releases/download/v9.8.7/' + asset + '\n', self.log('curl'))
                self.assertIn('/releases/download/v9.8.7/' + asset + '.sha256\n', self.log('curl'))
                self.assertEqual(self.log('build'), '')

    def test_pinned_versions_skip_latest_lookup(self):
        for version in ['0.1.2', 'v0.1.2']:
            with self.subTest(version=version):
                self.installed(self.run_install(**{PREFIX+'_VERSION': version, 'FAIL_LATEST':'1'}))
                self.assertNotIn('/releases/latest', self.log('curl'))
                self.assertIn('/releases/download/v0.1.2/', self.log('curl'))

    def test_exotic_and_forced_source_builds_use_the_selected_tag(self):
        for arch, forced in [('riscv64','0'), ('x86_64','1')]:
            with self.subTest(arch=arch):
                self.installed(self.run_install(arch=arch, **{PREFIX+'_VERSION':'v0.1.2', PREFIX+'_BUILD_FROM_SOURCE':forced, 'FAIL_LATEST':'1'}))
                if IS_GO:
                    self.assertIn('go1.26.0\ninstall\ngithub.com/ilvar/strictgo@v0.1.2\n', self.log('build'))
                else:
                    self.assertIn('--tag\nv0.1.2\n--locked\n', self.log('build'))
                    self.assertIn('toolchain\ninstall\n1.97.1\n', self.log('compiler'))
                self.assertEqual(self.log('curl'), '')

    def test_macos_checksum_fallback_works_without_gnu_tools(self):
        self.installed(self.run_install('Darwin', 'arm64', FORCE_SHASUM='1'))
        self.assertEqual(self.log('build'), '')

    def test_invalid_versions_fail_before_download_or_build(self):
        for version in ['main', '../v0.1.2', 'vv0.1.2', '0.1', '0.1.2;touch file']:
            with self.subTest(version=version):
                result = self.run_install(**{PREFIX+'_VERSION':version})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.log('curl'), '')
                self.assertEqual(self.log('build'), '')

    def test_empty_and_explicit_latest_are_latest(self):
        for version in ['', 'latest']:
            with self.subTest(version=version):
                self.installed(self.run_install(**{PREFIX+'_VERSION':version}))
                self.assertIn('/releases/latest', self.log('curl'))

    def test_failures_preserve_existing_binary(self):
        for arch, flag in [('x86_64','BAD_CHECKSUM'), ('x86_64','FAIL_DOWNLOAD'), ('x86_64','FAIL_LATEST'), ('riscv64','FAIL_BUILD')]:
            with self.subTest(flag=flag):
                (self.dest/TOOL).write_text('existing install')
                result = self.run_install(arch=arch, **{flag:'1'})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((self.dest/TOOL).read_text(), 'existing install')

if __name__ == '__main__':
    unittest.main()
