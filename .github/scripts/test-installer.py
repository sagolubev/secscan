"""Exercise the real POSIX installer with local release fixtures, without network."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


INSTALLER = Path(__file__).resolve().parents[2] / "install.sh"
REPOSITORY = "https://github.com/sagolubev/secscan"


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="secscan-installer-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.tmp = self.root / "temporary downloads"
        self.tmp.mkdir()
        self.destination = self.root / "installed with spaces"
        self.log = self.root / "requests.jsonl"
        self.executed = self.root / "executed"
        self.env = dict(os.environ)
        self.env.update(PATH=str(self.bin), TMPDIR=str(self.tmp),
                        SC_TEST_OS="Linux", SC_TEST_ARCH="x86_64",
                        SC_TEST_VERSION="v0.2.0", SC_TEST_LOG=str(self.log),
                        SC_TEST_EXECUTED=str(self.executed))
        for name in ("awk", "grep", "mktemp", "mkdir", "cp", "chmod", "mv", "rm",
                     "sha256sum", "shasum", "tr"):
            command = shutil.which(name)
            if command:
                (self.bin / name).symlink_to(command)
        self.script("uname", "import os,sys\nprint(os.environ['SC_TEST_OS' if sys.argv[1] == '-s' else 'SC_TEST_ARCH'])\n")
        self.script("curl", r'''
import hashlib,json,os,pathlib,sys
args=sys.argv[1:]
url=next(arg for arg in args if arg.startswith('https://'))
with open(os.environ['SC_TEST_LOG'],'a') as log: log.write(json.dumps(args)+'\n')
if os.environ.get('SC_TEST_NETWORK_FAILURE'): sys.exit(22)
version=os.environ['SC_TEST_VERSION']
if url.endswith('/releases/latest'):
    print(os.environ.get('SC_TEST_LATEST_URL','https://github.com/sagolubev/secscan/releases/tag/'+version),end='')
    sys.exit(0)
prefix='https://github.com/sagolubev/secscan/releases/download/'+version+'/'
if not url.startswith(prefix): sys.exit(22)
asset=url[len(prefix):]
output=pathlib.Path(args[args.index('--output')+1])
reported='v0.0.0' if os.environ.get('SC_TEST_WRONG_VERSION') else version
payload=('#!/bin/sh\n: > "$SC_TEST_EXECUTED"\nprintf "%s\\n" "secscan '+reported+'"\n').encode()
if asset == 'SHA256SUMS':
    digest='0'*64 if os.environ.get('SC_TEST_BAD_CHECKSUM') else hashlib.sha256(payload).hexdigest()
    lines=[digest+'  secscan-'+platform+'\n' for platform in ('linux-amd64','linux-arm64','darwin-amd64','darwin-arm64')]
    if os.environ.get('SC_TEST_DUPLICATE_CHECKSUM'): lines+=lines
    if os.environ.get('SC_TEST_MISSING_CHECKSUM'): lines=[]
    if os.environ.get('SC_TEST_MALFORMED_CHECKSUM'): lines=[line.rstrip('\n')+' EXTRA\n' for line in lines]
    output.write_text(''.join(lines))
elif asset in ('secscan-linux-amd64','secscan-linux-arm64','secscan-darwin-amd64','secscan-darwin-arm64'):
    output.write_bytes(payload)
else: sys.exit(22)
''')

    def script(self, name, body):
        path = self.bin / name
        path.write_text(f"#!{sys.executable}\n" + body)
        path.chmod(0o755)

    def invoke(self, *args):
        return subprocess.run(["/bin/sh", "-s", "--", "--dir", str(self.destination), *args],
                              input=INSTALLER.read_text(), text=True, capture_output=True,
                              env=self.env, timeout=20)

    def requests(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def assert_clean(self):
        self.assertEqual(list(self.tmp.iterdir()), [])
        if self.destination.is_dir():
            self.assertEqual(list(self.destination.glob(".secscan.*")), [])

    def test_platforms_and_latest_release(self):
        for system, architecture, asset in [
            ("Linux", "x86_64", "linux-amd64"), ("Linux", "aarch64", "linux-arm64"),
            ("Darwin", "x86_64", "darwin-amd64"), ("Darwin", "arm64", "darwin-arm64"),
        ]:
            with self.subTest(system=system, architecture=architecture):
                self.env.update(SC_TEST_OS=system, SC_TEST_ARCH=architecture)
                self.log.unlink(missing_ok=True)
                result = self.invoke()
                self.assertEqual(result.returncode, 0, result.stderr)
                urls = [next(arg for arg in args if arg.startswith("https://")) for args in self.requests()]
                self.assertEqual(urls, [REPOSITORY + "/releases/latest",
                                       REPOSITORY + "/releases/download/v0.2.0/secscan-" + asset,
                                       REPOSITORY + "/releases/download/v0.2.0/SHA256SUMS"])
                self.assertEqual((self.destination / "secscan").stat().st_mode & 0o777, 0o755)
                self.assertTrue(self.executed.exists())
                self.assertEqual(self.destination.stat().st_mode & 0o777, 0o700)
                self.assert_clean()

    def test_pinned_version_and_upgrade(self):
        self.env["SC_TEST_VERSION"] = "v1.2.3"
        self.destination.mkdir()
        (self.destination / "secscan").write_text("old installation")
        result = self.invoke("--version", "v1.2.3")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("releases/latest", json.dumps(self.requests()))
        self.assertIn("v1.2.3", (self.destination / "secscan").read_text())
        self.assert_clean()

    def test_failures_preserve_previous_installation(self):
        self.destination.mkdir()
        previous = self.destination / "secscan"
        previous.write_text("old installation")
        for failure in ("SC_TEST_BAD_CHECKSUM", "SC_TEST_DUPLICATE_CHECKSUM",
                        "SC_TEST_MISSING_CHECKSUM", "SC_TEST_NETWORK_FAILURE", "SC_TEST_WRONG_VERSION",
                        "SC_TEST_MALFORMED_CHECKSUM"):
            with self.subTest(failure=failure):
                self.executed.unlink(missing_ok=True)
                self.env[failure] = "1"
                result = self.invoke()
                del self.env[failure]
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(previous.read_text(), "old installation")
                if failure != "SC_TEST_WRONG_VERSION":
                    self.assertFalse(self.executed.exists(), "unchecked executable ran")
                self.assert_clean()

    def test_unsupported_platform_and_bad_arguments(self):
        self.env["SC_TEST_OS"] = "FreeBSD"
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertEqual(self.requests(), [])
        self.env["SC_TEST_OS"] = "Linux"
        for args in (("--version", "v1.2.3;touch bad"), ("--version", "../other"),
                     ("--version",), ("--dir",), ("--unknown",), ("--dir", "")):
            with self.subTest(args=args):
                self.assertNotEqual(self.invoke(*args).returncode, 0)
                self.assertEqual(self.requests(), [])

    def test_version_must_be_one_line(self):
        result = self.invoke("--version", "v1.2.3\nv4.5.6")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.requests(), [])

    def test_destination_conflicts(self):
        self.destination.mkdir()
        target = self.destination / "secscan"
        other = self.root / "preserve"
        other.write_text("user file")
        target.symlink_to(other)
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertTrue(target.is_symlink())
        self.assertEqual(other.read_text(), "user file")
        target.unlink()
        target.mkdir()
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertEqual(list(target.iterdir()), [])
        self.assert_clean()

    def test_untrusted_latest_redirect(self):
        self.env["SC_TEST_LATEST_URL"] = "https://example.invalid/releases/tag/v0.2.0"
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertEqual(len(self.requests()), 1)
        self.assertFalse(self.destination.exists())
        self.assert_clean()


if __name__ == "__main__":
    unittest.main()
