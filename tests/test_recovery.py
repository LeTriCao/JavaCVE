"""Recovery configuration and transport checks; no upstream network or Java."""
import hashlib
import http.client
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from tools.maven_transport import official_transport
from tools.recover_builds import kotlin_overlay, jenkins_test_overlay


class RecoveryTests(unittest.TestCase):
    def test_kotlin_pin_uses_upstream_property_and_leaves_java_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "retrofit").mkdir()
            (root / "pom.xml").write_text('<project><kotlin.version>1.2.60</kotlin.version></project>')
            pom = root / "retrofit/pom.xml"
            pom.write_text('<plugin><artifactId>kotlin-maven-plugin</artifactId></plugin>')
            java = root / "retrofit/Example.java"
            java.write_bytes(b'class Example {}\n')
            overlay = kotlin_overlay(root)
            self.assertEqual(overlay["version"], "1.2.60")
            self.assertEqual(java.read_bytes(), b'class Example {}\n')
            self.assertNotEqual(overlay["original_sha256"], overlay["configured_sha256"])
            with self.assertRaisesRegex(ValueError, "already pinned"):
                kotlin_overlay(root)

    def test_unverified_kotlin_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text('<project><kotlin.version>2.5.0-RC</kotlin.version></project>')
            with self.assertRaisesRegex(ValueError, "Unexpected historical"):
                kotlin_overlay(root)

    def test_jenkins_overlay_disables_only_test_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "pom.xml").write_text('<project><parent><version>4.33</version></parent></project>')
            (source / "Example.java").write_bytes(b'class Example {}')
            jar = root / '.cache/m2/org/jenkins-ci/tools/maven-hpi-plugin/3.22/maven-hpi-plugin-3.22.jar'
            jar.parent.mkdir(parents=True)
            jar.write_bytes(b'plugin descriptor provenance fixture')
            with patch('tools.recover_builds.ROOT', root):
                overlay = jenkins_test_overlay(source)
            self.assertEqual(overlay['disabled_execution'], 'default-resolve-test-dependencies')
            self.assertEqual((source / 'Example.java').read_bytes(), b'class Example {}')
            self.assertIn('<phase>none</phase>', (source / 'pom.xml').read_text())
            self.assertEqual(overlay['plugin_descriptor_source_sha256'], hashlib.sha256(jar.read_bytes()).hexdigest())

    def test_transport_preserves_bytes_and_restricts_repository_routes(self):
        content = b'<project>known bytes</project>\n'
        class Response(io.BytesIO):
            status = 200
        with tempfile.TemporaryDirectory() as tmp:
            settings = Path(tmp) / "settings.xml"
            settings.write_text('<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"><mirrors><mirror><id>repro-central-https</id><mirrorOf>central</mirrorOf><url>https://repo.maven.apache.org/maven2/</url></mirror></mirrors></settings>')
            downloads = []
            with patch('tools.maven_transport.urllib.request.urlopen', return_value=Response(content)) as fetch:
                with official_transport(settings, downloads):
                    self.assertIn('<settings xmlns=', settings.read_text())
                    self.assertNotIn('ns0:settings', settings.read_text())
                    node = ET.parse(settings).find('.//{*}url')
                    port = int(node.text.split(':')[2].split('/')[0])
                    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                    conn.request('GET', '/central/example/test.pom')
                    response = conn.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.read(), content)
                    conn.close()
                    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                    conn.request('GET', '/unknown/secret')
                    response = conn.getresponse()
                    self.assertEqual(response.status, 400)
                    response.read()
                    conn.close()
            self.assertEqual(downloads, [{'url': 'https://repo.maven.apache.org/maven2/example/test.pom',
                                         'status': 200, 'bytes': len(content), 'method': 'GET', 'sha256': hashlib.sha256(content).hexdigest()}])
            fetch.assert_called_once()
