"""Filesystem upgrade checks; no running app, codesign service or network is used."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class AppInstallTests(unittest.TestCase):
    def module(self):
        path = Path(__file__).resolve().parents[1] / 'script/install_app.py'
        spec = importlib.util.spec_from_file_location('install_app', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def bundle(self, path, value):
        (path / 'Contents/MacOS').mkdir(parents=True)
        (path / 'Contents/MacOS/EZSwitch').write_text(value)
        return path

    def invoke(self, module, root, **kwargs):
        return module.install_bundle(root / 'build/EZ Route.app', root / 'Applications/EZ Route.app',
            root / 'Applications/EZSwitch.app', root / 'backups',
            verify=kwargs.get('verify', lambda path: None),
            quit_app=kwargs.get('quit_app', lambda: None), launch=kwargs.get('launch', lambda path: None))

    def test_upgrade_moves_legacy_app_to_backup(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.bundle(root / 'build/EZ Route.app', 'new')
            legacy = self.bundle(root / 'Applications/EZSwitch.app', 'old')
            result = self.invoke(module, root)
            self.assertFalse(legacy.exists())
            self.assertEqual((root / 'Applications/EZ Route.app/Contents/MacOS/EZSwitch').read_text(), 'new')
            self.assertEqual(len(result['backups']), 1)
            self.assertEqual((Path(result['backups'][0]) / 'Contents/MacOS/EZSwitch').read_text(), 'old')

    def test_both_previous_names_are_backed_up(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.bundle(root / 'build/EZ Route.app', 'new')
            self.bundle(root / 'Applications/EZ Route.app', 'previous-route')
            self.bundle(root / 'Applications/EZSwitch.app', 'previous-switch')
            result = self.invoke(module, root)
            self.assertEqual({(Path(p) / 'Contents/MacOS/EZSwitch').read_text() for p in result['backups']},
                             {'previous-route', 'previous-switch'})

    def test_signature_failure_keeps_old_app_and_does_not_quit(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.bundle(root / 'build/EZ Route.app', 'bad')
            legacy = self.bundle(root / 'Applications/EZSwitch.app', 'old')
            quits = []
            def reject(path):
                raise RuntimeError('invalid signature')
            with self.assertRaisesRegex(RuntimeError, 'invalid signature'):
                self.invoke(module, root, verify=reject, quit_app=lambda: quits.append(True))
            self.assertEqual(quits, [])
            self.assertEqual((legacy / 'Contents/MacOS/EZSwitch').read_text(), 'old')

    def test_refused_quit_keeps_old_app(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.bundle(root / 'build/EZ Route.app', 'new')
            legacy = self.bundle(root / 'Applications/EZSwitch.app', 'old')
            def refuse():
                raise RuntimeError('still running')
            with self.assertRaisesRegex(RuntimeError, 'still running'):
                self.invoke(module, root, quit_app=refuse)
            self.assertTrue(legacy.exists())
            self.assertFalse((root / 'Applications/EZ Route.app').exists())

    def test_failed_replacement_restores_original_locations(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.bundle(root / 'build/EZ Route.app', 'new')
            legacy = self.bundle(root / 'Applications/EZSwitch.app', 'old')
            renamed = self.bundle(root / 'Applications/EZ Route.app', 'previous-route')
            rename = module.os.rename
            def fail_final_move(source, target):
                if Path(target) == renamed and '.ezroute-install-' in str(source):
                    raise OSError('replacement failed')
                return rename(source, target)
            with patch.object(module.os, 'rename', side_effect=fail_final_move):
                with self.assertRaisesRegex(OSError, 'replacement failed'):
                    self.invoke(module, root)
            self.assertEqual((legacy / 'Contents/MacOS/EZSwitch').read_text(), 'old')
            self.assertEqual((renamed / 'Contents/MacOS/EZSwitch').read_text(), 'previous-route')

    def test_failed_launch_restores_and_reopens_legacy_app(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.bundle(root / 'build/EZ Route.app', 'new')
            legacy = self.bundle(root / 'Applications/EZSwitch.app', 'old')
            launches = []
            def launch(path):
                launches.append(path)
                if len(launches) == 1:
                    raise OSError('launch failed')
            with self.assertRaisesRegex(OSError, 'launch failed'):
                self.invoke(module, root, launch=launch)
            self.assertFalse((root / 'Applications/EZ Route.app').exists())
            self.assertEqual((legacy / 'Contents/MacOS/EZSwitch').read_text(), 'old')
            self.assertEqual(launches, [root / 'Applications/EZ Route.app', legacy])

    def test_failed_launch_restores_both_previous_app_names(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.bundle(root / 'build/EZ Route.app', 'new')
            legacy = self.bundle(root / 'Applications/EZSwitch.app', 'old')
            renamed = self.bundle(root / 'Applications/EZ Route.app', 'previous-route')
            launches = []
            def launch(path):
                launches.append(path)
                if len(launches) == 1:
                    raise OSError('launch failed')
            with self.assertRaisesRegex(OSError, 'launch failed'):
                self.invoke(module, root, launch=launch)
            self.assertEqual((legacy / 'Contents/MacOS/EZSwitch').read_text(), 'old')
            self.assertEqual((renamed / 'Contents/MacOS/EZSwitch').read_text(), 'previous-route')
            self.assertEqual(launches, [renamed, renamed])
