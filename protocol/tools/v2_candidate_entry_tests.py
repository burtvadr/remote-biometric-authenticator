#!/usr/bin/env python3
"""Static candidate entry-point contract; not APK/daemon execution evidence."""
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
ANDROID = '{http://schemas.android.com/apk/res/android}'

def attr(element, name):
    return element.get(ANDROID + name)

class CandidateEntryTests(unittest.TestCase):
    def setUp(self):
        self.manifest = ET.parse(ROOT / 'android/app/src/main/AndroidManifest.xml').getroot()
        self.app = self.manifest.find('application')

    def test_only_v2_components(self):
        self.assertEqual({attr(x, 'name') for x in self.app.findall('activity')},
                         {'.ui.v2.V2OperatorActivity', '.ui.v2.V2NotificationActivity'})
        self.assertEqual([attr(x, 'name') for x in self.app.findall('service')],
                         ['.service.V2BackgroundService'])
        self.assertEqual(self.app.findall('receiver'), [])
        self.assertIsNone(attr(self.app, 'name'))

    def test_only_launcher_exported(self):
        components = [x for x in self.app if x.tag in ('activity', 'activity-alias', 'service', 'receiver', 'provider')]
        self.assertEqual([attr(x, 'name') for x in components if attr(x, 'exported') == 'true'], ['.V2Launcher'])
        aliases = self.app.findall('activity-alias')
        self.assertEqual(len(aliases), 1)
        self.assertEqual(attr(aliases[0], 'targetActivity'), '.ui.v2.V2OperatorActivity')
        self.assertEqual([attr(x, 'name') for x in aliases[0].findall('intent-filter/category')], ['android.intent.category.LAUNCHER'])
        for x in components:
            if x.tag != 'activity-alias':
                self.assertEqual(attr(x, 'exported'), 'false')
                self.assertEqual(x.findall('intent-filter'), [])

    def test_minimal_permissions(self):
        self.assertEqual({attr(x, 'name') for x in self.manifest.findall('uses-permission')}, {
            'android.permission.INTERNET', 'android.permission.USE_BIOMETRIC',
            'android.permission.FOREGROUND_SERVICE', 'android.permission.FOREGROUND_SERVICE_SPECIAL_USE',
            'android.permission.POST_NOTIFICATIONS'})
        self.assertEqual(attr(self.app.find('service'), 'foregroundServiceType'), 'specialUse')
        self.assertEqual(attr(self.app, 'allowBackup'), 'false')
        self.assertEqual(attr(self.app, 'usesCleartextTraffic'), 'false')

    def test_legacy_daemon_entry_is_absent(self):
        main = (ROOT / 'linux/rbad/src/main.rs').read_text()
        public = (ROOT / 'linux/rba/src/main.rs').read_text()
        lifecycle = (ROOT / 'linux/rbad/src/v2_tls/candidate/lifecycle.rs').read_text()
        self.assertIn('candidate::entry()', main)
        self.assertIn('candidate::entry()', public)
        main += public + lifecycle
        for entry in ('Daemon::bootstrap', 'server::run', 'registry::', 'ipc::'):
            self.assertNotIn(entry, main)
        for entry in ('=>initialize(', '=>check(', '=>foreground('):
            self.assertIn(entry, main)

    def test_install_block_precedes_mutations(self):
        install = (ROOT / 'packaging/arch/install-local.sh').read_text()
        self.assertLess(install.index('system installation blocked'), install.index('groupadd --system'))
        for name in ('sudo', 'gdm', 'polkit'):
            script = (ROOT / f'packaging/arch/pam-{name}-rba.sh').read_text()
            self.assertLess(script.index('PAM enablement blocked'), script.index('    validate_timeout\n    require_root'))
            self.assertIn('rollback remains available'.lower(), script.lower())
        deb = (ROOT / 'packaging/debian/rba.postinst').read_text()
        self.assertLess(deb.index('package configuration blocked'), deb.index('groupadd --system'))

if __name__ == '__main__':
    unittest.main()
