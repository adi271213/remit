import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('offline_runner', ROOT / 'scripts/action_runner.py')
runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)


class OfflineRuntime(unittest.TestCase):
    def test_bundle_verification_needs_no_installer_or_subprocess(self):
        with patch('subprocess.run', side_effect=AssertionError('installer invoked')):
            self.assertEqual(runner.bootstrap(ROOT, Path('/unused')), Path(sys.executable))

    def test_altered_missing_extra_or_symlinked_bundle_file_fails(self):
        for kind in ('altered', 'missing', 'extra', 'symlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                target = root / 'vendor/pyyaml'
                shutil.copytree(ROOT / 'vendor/pyyaml', target, ignore=shutil.ignore_patterns('__pycache__'))
                path = target / 'yaml/scanner.py'
                if kind == 'altered': path.write_text('raise RuntimeError("not trusted")')
                elif kind == 'missing': path.unlink()
                elif kind == 'extra': (target / 'yaml/extra.py').write_text('')
                else:
                    other = root / 'external.py'; shutil.copyfile(path, other); path.unlink(); path.symlink_to(other)
                with self.assertRaises(OSError): runner.bootstrap(root, root)

    def test_isolated_entry_loads_only_bundled_yaml_without_site_packages(self):
        code = "import sys;sys.path.insert(0,sys.argv[1]);import yaml;assert yaml.__version__=='6.0.3';assert not yaml.__with_libyaml__;print(yaml.__file__)"
        cp = subprocess.run([sys.executable, '-I', '-S', '-c', code, str(ROOT / 'vendor/pyyaml')], capture_output=True, text=True, check=True)
        self.assertIn(str(ROOT / 'vendor/pyyaml'), cp.stdout)

    def test_release_versions_match_release(self):
        project = tomllib.loads((ROOT / 'pyproject.toml').read_text())
        spec = importlib.util.spec_from_file_location('release_version', ROOT / 'src/privilege_check/__init__.py')
        version = importlib.util.module_from_spec(spec); spec.loader.exec_module(version)
        self.assertEqual(project['project']['version'], version.__version__)
        self.assertEqual(version.__version__, '0.0.4')
