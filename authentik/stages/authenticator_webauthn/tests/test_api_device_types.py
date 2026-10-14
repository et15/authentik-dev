"""Test WebAuthn device type API"""

from uuid import uuid4

from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.core.tests.utils import create_test_admin_user
from authentik.stages.authenticator_webauthn.models import WebAuthnDeviceType


class TestWebAuthnDeviceTypeAPI(APITestCase):
    """Test WebAuthn device type API"""

    def setUp(self) -> None:
        self.user = create_test_admin_user()
        self.client.force_login(self.user)
        self.device_type = WebAuthnDeviceType.objects.create(
            aaguid=uuid4(),
            description="Test device type",
            attestation_root_certificates=["-----BEGIN CERTIFICATE-----"],
            key_protection=["hardware"],
        )

    def test_list(self):
        """The list can be fetched and filtered without exposing attestation internals"""
        url = reverse("authentik_api:webauthndevicetype-list")
        response = self.client.get(url, {"aaguid": str(self.device_type.aaguid)})
        self.assertEqual(response.status_code, 200)
        results = response.json()["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(set(results[0].keys()), {"aaguid", "description"})
