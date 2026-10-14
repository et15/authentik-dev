"""Test WebAuthn MDS import task"""

from django.apps import apps
from django.core.cache import cache
from django.test import TestCase
from fido2.mds3 import parse_blob

from authentik.stages.authenticator_webauthn.models import WebAuthnDeviceType
from authentik.stages.authenticator_webauthn.tasks import (
    CACHE_KEY_MDS_NO,
    CACHE_KEY_MDS_NO_PREFIX,
    MDS_BLOB_PATH,
    mds_ca,
    webauthn_mds_import,
)


class TestWebAuthnMDSImport(TestCase):
    """Test WebAuthn MDS import task"""

    def setUp(self) -> None:
        cache.delete(CACHE_KEY_MDS_NO)
        cache.delete(CACHE_KEY_MDS_NO_PREFIX)
        self.blob_no = parse_blob(MDS_BLOB_PATH.read_bytes(), mds_ca()).no

    def _with_trust_anchors(self):
        return WebAuthnDeviceType.objects.exclude(attestation_root_certificates=[])

    def _simulate_upgrade_from_before_trust_anchors(self):
        """State of an installation that imported this blob with an older version: the
        unversioned cache key holds the current blob number, the new columns are empty"""
        webauthn_mds_import.send(force=True)
        self.assertTrue(self._with_trust_anchors().exists())
        WebAuthnDeviceType.objects.update(attestation_root_certificates=[])
        cache.delete(CACHE_KEY_MDS_NO)
        cache.set(CACHE_KEY_MDS_NO_PREFIX, self.blob_no)

    def test_import_stores_trust_anchors(self):
        """Import persists the attestation root certificates of MDS entries as PEM"""
        webauthn_mds_import.send(force=True)
        device_type = self._with_trust_anchors().first()
        self.assertIsNotNone(device_type)
        for pem in device_type.attestation_root_certificates:
            self.assertIn("-----BEGIN CERTIFICATE-----", pem)

    def test_import_stores_key_protection(self):
        """Import persists the key protection types of MDS entries"""
        webauthn_mds_import.send(force=True)
        yubikey = (
            WebAuthnDeviceType.objects.filter(description__startswith="YubiKey 5")
            .exclude(key_protection=[])
            .first()
        )
        self.assertIsNotNone(yubikey)
        self.assertIn("hardware", yubikey.key_protection)
        self.assertIn("secure_element", yubikey.key_protection)

    def test_import_after_upgrade_repopulates_key_protection(self):
        """A blob imported by the version that only stored trust anchors (v2) is imported
        again, so key protection becomes available without force"""
        webauthn_mds_import.send(force=True)
        self.assertTrue(WebAuthnDeviceType.objects.exclude(key_protection=[]).exists())
        WebAuthnDeviceType.objects.update(key_protection=[])
        cache.delete(CACHE_KEY_MDS_NO)
        cache.set(f"{CACHE_KEY_MDS_NO_PREFIX}/v2", self.blob_no)
        webauthn_mds_import.send()
        self.assertTrue(WebAuthnDeviceType.objects.exclude(key_protection=[]).exists())

    def test_import_after_upgrade_repopulates(self):
        """An unchanged blob that was imported before trust anchors were stored is
        imported again, without needing force"""
        self._simulate_upgrade_from_before_trust_anchors()
        webauthn_mds_import.send()
        self.assertTrue(self._with_trust_anchors().exists())
        self.assertEqual(cache.get(CACHE_KEY_MDS_NO), self.blob_no)

    def test_import_skips_unchanged_blob(self):
        """Once imported at the current version, an unchanged blob is not imported again"""
        webauthn_mds_import.send(force=True)
        WebAuthnDeviceType.objects.update(attestation_root_certificates=[])
        webauthn_mds_import.send()
        self.assertFalse(self._with_trust_anchors().exists())

    def test_import_runs_on_startup(self):
        """The import is sent on startup so upgrades do not wait for the weekly schedule"""
        config = apps.get_app_config("authentik_stages_authenticator_webauthn")
        specs = [s for s in config.schedule_specs if s.actor is webauthn_mds_import]
        self.assertEqual(len(specs), 1)
        self.assertTrue(specs[0].send_on_startup)
