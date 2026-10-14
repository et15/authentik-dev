"""Test WebAuthn API"""

import os
from base64 import b64decode, urlsafe_b64decode
from json import loads
from uuid import UUID

from django.urls import reverse
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url
from webauthn.helpers.encode_cbor import encode_cbor
from webauthn.helpers.parse_cbor import parse_cbor

from authentik.core.tests.utils import create_test_admin_user, create_test_flow, create_test_user
from authentik.flows.markers import StageMarker
from authentik.flows.models import FlowStageBinding
from authentik.flows.planner import PLAN_CONTEXT_PENDING_USER, FlowPlan
from authentik.flows.tests import FlowTestCase
from authentik.flows.views.executor import SESSION_KEY_PLAN
from authentik.lib.generators import generate_id
from authentik.lib.tests.utils import load_fixture
from authentik.stages.authenticator_webauthn.models import (
    UNKNOWN_DEVICE_TYPE_AAGUID,
    AttestationRequirement,
    AuthenticatorWebAuthnStage,
    CredentialBackupEligibility,
    KeyProtectionMatchMode,
    WebAuthnDevice,
    WebAuthnDeviceType,
    WebAuthnHint,
)
from authentik.stages.authenticator_webauthn.stage import PLAN_CONTEXT_WEBAUTHN_CHALLENGE
from authentik.stages.authenticator_webauthn.tasks import webauthn_mds_import
from authentik.stages.authenticator_webauthn.tests.synthetic import (
    b64url,
    build_synthetic_packed_attestation,
    generate_test_root_ca,
)


class TestAuthenticatorWebAuthnStage(FlowTestCase):
    """Test WebAuthn API"""

    def setUp(self) -> None:
        self.stage = AuthenticatorWebAuthnStage.objects.create(
            name=generate_id(),
        )
        self.flow = create_test_flow()
        self.binding = FlowStageBinding.objects.create(
            target=self.flow,
            stage=self.stage,
            order=0,
        )
        self.user = create_test_admin_user()

    def test_api_delete(self):
        """Test api delete"""
        self.client.force_login(self.user)
        dev = WebAuthnDevice.objects.create(user=self.user)
        response = self.client.delete(
            reverse("authentik_api:webauthndevice-detail", kwargs={"pk": dev.pk})
        )
        self.assertEqual(response.status_code, 204)

    def test_registration_options(self):
        """Test registration options"""
        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        plan.context[PLAN_CONTEXT_PENDING_USER] = self.user
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()

        response = self.client.get(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
        )

        plan: FlowPlan = self.client.session[SESSION_KEY_PLAN]

        self.assertEqual(response.status_code, 200)
        session = self.client.session
        self.assertStageResponse(
            response,
            self.flow,
            self.user,
            registration={
                "rp": {"name": "authentik", "id": "testserver"},
                "user": {
                    "id": bytes_to_base64url(self.user.uid.encode("utf-8")),
                    "name": self.user.username,
                    "displayName": self.user.name,
                },
                "challenge": bytes_to_base64url(plan.context[PLAN_CONTEXT_WEBAUTHN_CHALLENGE]),
                "pubKeyCredParams": [
                    {"type": "public-key", "alg": -8},
                    {"type": "public-key", "alg": -7},
                    {"type": "public-key", "alg": -257},
                ],
                "timeout": 60000,
                "excludeCredentials": [],
                "authenticatorSelection": {
                    "residentKey": "preferred",
                    "requireResidentKey": False,
                    "userVerification": "preferred",
                },
                "attestation": "direct",
            },
        )

    def test_register(self):
        """Test registration"""
        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        plan.context[PLAN_CONTEXT_PENDING_USER] = self.user
        plan.context[PLAN_CONTEXT_WEBAUTHN_CHALLENGE] = b64decode(
            b"iHIX3AtkZZCxSYLxOhk80ZXI7RnAC0Pb4WTk9dEJ4eLJdzoh8jRmjKW2U9oE/CBn5n6Zj67BIIZvFL3lpiwJwg=="
        )
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()
        response = self.client.post(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
            data={
                "component": "ak-stage-authenticator-webauthn",
                "response": loads(load_fixture("fixtures/register.json")),
            },
            SERVER_NAME="localhost",
            SERVER_PORT="9000",
        )
        self.assertEqual(response.status_code, 200)
        self.assertStageRedirects(response, reverse("authentik_core:root-redirect"))
        device = WebAuthnDevice.objects.filter(user=self.user).first()
        self.assertIsNotNone(device)
        self.assertEqual(
            device.credential_id, "f7wv8mP-poSxh-567eWxZntzCBDW8hWlvzf92QJkT--Y2oBRz4IEAZ6M2PI9_KEQ"
        )
        self.assertEqual(
            device.attestation_certificate_fingerprint,
            "3e:28:fc:df:45:19:bb:94:0a:0c:90:98:f2:08:72:53:2a:9e:e2:76:13:02:3e:69:61:4a:d9:90:49:80:3d:34",
        )

    def test_register_shared_attestation_certificate(self):
        """Test that a device sharing an attestation certificate with an existing device of
        another user can still be registered.

        Attestation certificates are shared across entire manufacturing batches, so they must
        never be treated as identifying an individual device."""
        WebAuthnDevice.objects.create(
            user=create_test_user(),
            name=generate_id(),
            credential_id=bytes_to_base64url(b"batch-sibling-credential"),
            rp_id="localhost",
            attestation_certificate_fingerprint=(
                "3e:28:fc:df:45:19:bb:94:0a:0c:90:98:f2:08:72:53:"
                "2a:9e:e2:76:13:02:3e:69:61:4a:d9:90:49:80:3d:34"
            ),
        )

        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        plan.context[PLAN_CONTEXT_PENDING_USER] = self.user
        plan.context[PLAN_CONTEXT_WEBAUTHN_CHALLENGE] = b64decode(
            b"iHIX3AtkZZCxSYLxOhk80ZXI7RnAC0Pb4WTk9dEJ4eLJdzoh8jRmjKW2U9oE/CBn5n6Zj67BIIZvFL3lpiwJwg=="
        )
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()
        response = self.client.post(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
            data={
                "component": "ak-stage-authenticator-webauthn",
                "response": loads(load_fixture("fixtures/register.json")),
            },
            SERVER_NAME="localhost",
            SERVER_PORT="9000",
        )
        self.assertEqual(response.status_code, 200)
        self.assertStageRedirects(response, reverse("authentik_core:root-redirect"))
        self.assertTrue(WebAuthnDevice.objects.filter(user=self.user).exists())

    def test_register_restricted_device_type_deny(self):
        """Test registration with restricted devices (fail)"""
        webauthn_mds_import.send(force=True)
        self.stage.device_type_restrictions.set(
            WebAuthnDeviceType.objects.filter(description="YubiKey 5 Series")
        )

        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        plan.context[PLAN_CONTEXT_PENDING_USER] = self.user
        plan.context[PLAN_CONTEXT_WEBAUTHN_CHALLENGE] = b64decode(
            b"03Xodi54gKsfnP5I9VFfhaGXVVE2NUyZpBBXns/JI+x6V9RY2Tw2QmxRJkhh7174EkRazUntIwjMVY9bFG60Lw=="
        )
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()
        response = self.client.post(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
            data={
                "component": "ak-stage-authenticator-webauthn",
                "response": {
                    "id": "kqnmrVLnDG-OwsSNHkihYZaNz5s",
                    "rawId": "kqnmrVLnDG-OwsSNHkihYZaNz5s",
                    "type": "public-key",
                    "registrationClientExtensions": "{}",
                    "response": {
                        "clientDataJSON": (
                            "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmd"
                            "lIjoiMDNYb2RpNTRnS3NmblA1STlWRmZoYUdYVlZFMk5VeV"
                            "pwQkJYbnNfSkkteDZWOVJZMlR3MlFteFJKa2hoNzE3NEVrU"
                            "mF6VW50SXdqTVZZOWJGRzYwTHciLCJvcmlnaW4iOiJodHRw"
                            "Oi8vbG9jYWxob3N0OjkwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
                        ),
                        "attestationObject": (
                            "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5Yg"
                            "OjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAPv8MA"
                            "cVTk7MjAtuAgVX170AFJKp5q1S5wxvjsLEjR5IoWGWjc-bp"
                            "QECAyYgASFYIKtcZHPumH37XHs0IM1v3pUBRIqHVV_SE-Lq"
                            "2zpJAOVXIlgg74Fg_WdB0kuLYqCKbxogkEPaVtR_iR3IyQFIJAXBzds"
                        ),
                    },
                },
            },
            SERVER_NAME="localhost",
            SERVER_PORT="9000",
        )
        self.assertEqual(response.status_code, 200)
        self.assertStageResponse(
            response,
            flow=self.flow,
            component="ak-stage-authenticator-webauthn",
            response_errors={
                "response": [
                    {
                        "string": (
                            "Invalid device type. Contact your authentik administrator for help."
                        ),
                        "code": "invalid",
                    }
                ]
            },
        )
        self.assertFalse(WebAuthnDevice.objects.filter(user=self.user).exists())

    def test_register_restricted_device_type_allow(self):
        """Test registration with restricted devices (allow)"""
        webauthn_mds_import.send(force=True)
        self.stage.device_type_restrictions.set(
            WebAuthnDeviceType.objects.filter(description="iCloud Keychain")
        )

        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        plan.context[PLAN_CONTEXT_PENDING_USER] = self.user
        plan.context[PLAN_CONTEXT_WEBAUTHN_CHALLENGE] = b64decode(
            b"03Xodi54gKsfnP5I9VFfhaGXVVE2NUyZpBBXns/JI+x6V9RY2Tw2QmxRJkhh7174EkRazUntIwjMVY9bFG60Lw=="
        )
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()
        response = self.client.post(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
            data={
                "component": "ak-stage-authenticator-webauthn",
                "response": {
                    "id": "kqnmrVLnDG-OwsSNHkihYZaNz5s",
                    "rawId": "kqnmrVLnDG-OwsSNHkihYZaNz5s",
                    "type": "public-key",
                    "registrationClientExtensions": "{}",
                    "response": {
                        "clientDataJSON": (
                            "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmd"
                            "lIjoiMDNYb2RpNTRnS3NmblA1STlWRmZoYUdYVlZFMk5VeV"
                            "pwQkJYbnNfSkkteDZWOVJZMlR3MlFteFJKa2hoNzE3NEVrU"
                            "mF6VW50SXdqTVZZOWJGRzYwTHciLCJvcmlnaW4iOiJodHRw"
                            "Oi8vbG9jYWxob3N0OjkwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
                        ),
                        "attestationObject": (
                            "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5Yg"
                            "OjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAPv8MA"
                            "cVTk7MjAtuAgVX170AFJKp5q1S5wxvjsLEjR5IoWGWjc-bp"
                            "QECAyYgASFYIKtcZHPumH37XHs0IM1v3pUBRIqHVV_SE-Lq"
                            "2zpJAOVXIlgg74Fg_WdB0kuLYqCKbxogkEPaVtR_iR3IyQFIJAXBzds"
                        ),
                    },
                },
            },
            SERVER_NAME="localhost",
            SERVER_PORT="9000",
        )
        self.assertEqual(response.status_code, 200)
        self.assertStageRedirects(response, reverse("authentik_core:root-redirect"))
        self.assertTrue(WebAuthnDevice.objects.filter(user=self.user).exists())

    def test_register_restricted_device_type_allow_unknown(self):
        """Test registration with restricted devices (allow, unknown device type)"""
        webauthn_mds_import.send(force=True)
        WebAuthnDeviceType.objects.filter(aaguid="fbfc3007-154e-4ecc-8c0b-6e020557d7bd").delete()
        self.stage.device_type_restrictions.set(
            WebAuthnDeviceType.objects.filter(aaguid=UNKNOWN_DEVICE_TYPE_AAGUID)
        )

        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        plan.context[PLAN_CONTEXT_PENDING_USER] = self.user
        plan.context[PLAN_CONTEXT_WEBAUTHN_CHALLENGE] = b64decode(
            b"03Xodi54gKsfnP5I9VFfhaGXVVE2NUyZpBBXns/JI+x6V9RY2Tw2QmxRJkhh7174EkRazUntIwjMVY9bFG60Lw=="
        )
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()
        response = self.client.post(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
            data={
                "component": "ak-stage-authenticator-webauthn",
                "response": {
                    "id": "kqnmrVLnDG-OwsSNHkihYZaNz5s",
                    "rawId": "kqnmrVLnDG-OwsSNHkihYZaNz5s",
                    "type": "public-key",
                    "registrationClientExtensions": "{}",
                    "response": {
                        "clientDataJSON": (
                            "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmd"
                            "lIjoiMDNYb2RpNTRnS3NmblA1STlWRmZoYUdYVlZFMk5VeV"
                            "pwQkJYbnNfSkkteDZWOVJZMlR3MlFteFJKa2hoNzE3NEVrU"
                            "mF6VW50SXdqTVZZOWJGRzYwTHciLCJvcmlnaW4iOiJodHRw"
                            "Oi8vbG9jYWxob3N0OjkwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
                        ),
                        "attestationObject": (
                            "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5Yg"
                            "OjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAPv8MA"
                            "cVTk7MjAtuAgVX170AFJKp5q1S5wxvjsLEjR5IoWGWjc-bp"
                            "QECAyYgASFYIKtcZHPumH37XHs0IM1v3pUBRIqHVV_SE-Lq"
                            "2zpJAOVXIlgg74Fg_WdB0kuLYqCKbxogkEPaVtR_iR3IyQFIJAXBzds"
                        ),
                    },
                },
            },
            SERVER_NAME="localhost",
            SERVER_PORT="9000",
        )
        self.assertEqual(response.status_code, 200)
        self.assertStageRedirects(response, reverse("authentik_core:root-redirect"))
        self.assertTrue(WebAuthnDevice.objects.filter(user=self.user).exists())

    def test_registration_options_with_hints(self):
        """Test that hints are included in registration options"""
        self.stage.hints = [WebAuthnHint.CLIENT_DEVICE, WebAuthnHint.SECURITY_KEY]
        self.stage.save()

        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        plan.context[PLAN_CONTEXT_PENDING_USER] = self.user
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()

        response = self.client.get(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
        )
        self.assertEqual(response.status_code, 200)
        registration = response.json()["registration"]
        self.assertEqual(registration["hints"], ["client-device", "security-key"])

    def test_registration_options_hints_empty(self):
        """Test that no hints key is present when hints are empty"""
        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        plan.context[PLAN_CONTEXT_PENDING_USER] = self.user
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()

        response = self.client.get(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
        )
        self.assertEqual(response.status_code, 200)
        registration = response.json()["registration"]
        self.assertNotIn("hints", registration)

    def test_registration_options_hints_infer_attachment_cross_platform(self):
        """Test that authenticatorAttachment is auto-inferred as cross-platform
        from security-key/hybrid hints for backwards compatibility"""
        self.stage.hints = [WebAuthnHint.SECURITY_KEY]
        self.stage.authenticator_attachment = None
        self.stage.save()

        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        plan.context[PLAN_CONTEXT_PENDING_USER] = self.user
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()

        response = self.client.get(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
        )
        self.assertEqual(response.status_code, 200)
        registration = response.json()["registration"]
        self.assertEqual(
            registration["authenticatorSelection"]["authenticatorAttachment"], "cross-platform"
        )

    def test_registration_options_hints_infer_attachment_platform(self):
        """Test that authenticatorAttachment is auto-inferred as platform
        from client-device hint for backwards compatibility"""
        self.stage.hints = [WebAuthnHint.CLIENT_DEVICE]
        self.stage.authenticator_attachment = None
        self.stage.save()

        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        plan.context[PLAN_CONTEXT_PENDING_USER] = self.user
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()

        response = self.client.get(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
        )
        self.assertEqual(response.status_code, 200)
        registration = response.json()["registration"]
        self.assertEqual(
            registration["authenticatorSelection"]["authenticatorAttachment"], "platform"
        )

    def test_registration_options_hints_no_infer_when_attachment_set(self):
        """Test that authenticatorAttachment is NOT overridden when explicitly set"""
        self.stage.hints = [WebAuthnHint.SECURITY_KEY]
        self.stage.authenticator_attachment = "platform"
        self.stage.save()

        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        plan.context[PLAN_CONTEXT_PENDING_USER] = self.user
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()

        response = self.client.get(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
        )
        self.assertEqual(response.status_code, 200)
        registration = response.json()["registration"]
        self.assertEqual(
            registration["authenticatorSelection"]["authenticatorAttachment"], "platform"
        )

    def test_registration_options_hints_no_infer_mixed(self):
        """Test that authenticatorAttachment is NOT inferred when hints are mixed"""
        self.stage.hints = [WebAuthnHint.SECURITY_KEY, WebAuthnHint.CLIENT_DEVICE]
        self.stage.authenticator_attachment = None
        self.stage.save()

        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        plan.context[PLAN_CONTEXT_PENDING_USER] = self.user
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()

        response = self.client.get(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
        )
        self.assertEqual(response.status_code, 200)
        registration = response.json()["registration"]
        self.assertNotIn("authenticatorAttachment", registration["authenticatorSelection"])

    def test_registration_options_hints_order_preserved(self):
        """Test that hint order is preserved (first hint = highest priority)"""
        self.stage.hints = [
            WebAuthnHint.HYBRID,
            WebAuthnHint.CLIENT_DEVICE,
            WebAuthnHint.SECURITY_KEY,
        ]
        self.stage.save()

        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        plan.context[PLAN_CONTEXT_PENDING_USER] = self.user
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()

        response = self.client.get(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
        )
        self.assertEqual(response.status_code, 200)
        registration = response.json()["registration"]
        self.assertEqual(registration["hints"], ["hybrid", "client-device", "security-key"])

    def test_register_max_retries(self):
        """Test registration (exceeding max retries)"""
        self.stage.max_attempts = 2
        self.stage.save()

        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        plan.context[PLAN_CONTEXT_PENDING_USER] = self.user
        plan.context[PLAN_CONTEXT_WEBAUTHN_CHALLENGE] = b64decode(
            b"03Xodi54gKsfnP5I9VFfhaGXVVE2NUyZpBBXns/JI+x6V9RY2Tw2QmxRJkhh7174EkRazUntIwjMVY9bFG60Lw=="
        )
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()

        # first failed request
        response = self.client.post(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
            data={
                "component": "ak-stage-authenticator-webauthn",
                "response": {
                    "id": "kqnmrVLnDG-OwsSNHkihYZaNz5s",
                    "rawId": "kqnmrVLnDG-OwsSNHkihYZaNz5s",
                    "type": "public-key",
                    "registrationClientExtensions": "{}",
                    "response": {
                        "clientDataJSON": (
                            "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmd"
                            "lIjoiMDNYb2RpNTRnS3NmblA1STlWRmZoYUdYVlZFMk5VeV"
                            "pwQkJYbnNfSkkteDZWOVJZMlR3MlFteFJKa2hoNzE3NEVrU"
                            "mF6VW50SXdqTVZZOWJGRzYwTHciLCJvcmlnaW4iOiJodHRw"
                            "Oi8vbG9jYWxob3N0OjkwMDAiLCJjcm9zc09yaWdpbiI6ZmF"
                        ),
                        "attestationObject": (
                            "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5Yg"
                            "OjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAPv8MA"
                            "cVTk7MjAtuAgVX170AFJKp5q1S5wxvjsLEjR5IoWGWjc-bp"
                            "QECAyYgASFYIKtcZHPumH37XHs0IM1v3pUBRIqHVV_SE-Lq"
                            "2zpJAOVXIlgg74Fg_WdB0kuLYqCKbxogkEPaVtR_iR3IyQFIJAXBzds"
                        ),
                    },
                },
            },
            SERVER_NAME="localhost",
            SERVER_PORT="9000",
        )
        self.assertEqual(response.status_code, 200)
        self.assertStageResponse(
            response,
            flow=self.flow,
            component="ak-stage-authenticator-webauthn",
            response_errors={
                "response": [
                    {
                        "string": "Registration failed. Please contact your administrator.",
                        "code": "invalid",
                    }
                ]
            },
        )
        self.assertFalse(WebAuthnDevice.objects.filter(user=self.user).exists())

        # Second failed request
        response = self.client.post(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
            data={
                "component": "ak-stage-authenticator-webauthn",
                "response": {
                    "id": "kqnmrVLnDG-OwsSNHkihYZaNz5s",
                    "rawId": "kqnmrVLnDG-OwsSNHkihYZaNz5s",
                    "type": "public-key",
                    "registrationClientExtensions": "{}",
                    "response": {
                        "clientDataJSON": (
                            "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmd"
                            "lIjoiMDNYb2RpNTRnS3NmblA1STlWRmZoYUdYVlZFMk5VeV"
                            "pwQkJYbnNfSkkteDZWOVJZMlR3MlFteFJKa2hoNzE3NEVrU"
                            "mF6VW50SXdqTVZZOWJGRzYwTHciLCJvcmlnaW4iOiJodHRw"
                            "Oi8vbG9jYWxob3N0OjkwMDAiLCJjcm9zc09yaWdpbiI6ZmF"
                        ),
                        "attestationObject": (
                            "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5Yg"
                            "OjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAPv8MA"
                            "cVTk7MjAtuAgVX170AFJKp5q1S5wxvjsLEjR5IoWGWjc-bp"
                            "QECAyYgASFYIKtcZHPumH37XHs0IM1v3pUBRIqHVV_SE-Lq"
                            "2zpJAOVXIlgg74Fg_WdB0kuLYqCKbxogkEPaVtR_iR3IyQFIJAXBzds"
                        ),
                    },
                },
            },
            SERVER_NAME="localhost",
            SERVER_PORT="9000",
        )
        self.assertEqual(response.status_code, 200)
        self.assertStageResponse(
            response,
            flow=self.flow,
            component="ak-stage-access-denied",
            error_message=(
                "Exceeded maximum attempts. Contact your authentik administrator for help."
            ),
        )
        self.assertFalse(WebAuthnDevice.objects.filter(user=self.user).exists())

    # The two fixtures below intentionally cover both ends of the WebAuthn Backup Eligibility
    # (BE) flag:
    #   - "fixtures/register.json" carries BE=0/BS=0 (a single-device, hardware-bound
    #     credential).
    #   - The inline attestation below carries BE=1/BS=1 (a multi-device, syncable "iCloud
    #     Keychain" credential, also used by the device-type-restriction tests above).

    def test_register_backup_denied_applies_to_unknown_device_types(self):
        """backup_eligibility is still enforced when the device type restriction passes via
        the special "unknown devices" entry (regression: this used to return early)"""
        webauthn_mds_import.send(force=True)
        WebAuthnDeviceType.objects.filter(aaguid="fbfc3007-154e-4ecc-8c0b-6e020557d7bd").delete()
        self.stage.device_type_restrictions.set(
            WebAuthnDeviceType.objects.filter(aaguid=UNKNOWN_DEVICE_TYPE_AAGUID)
        )
        self.stage.backup_eligibility = CredentialBackupEligibility.DENIED
        self.stage.save()
        self._prepare_plan(
            b64decode(
                b"03Xodi54gKsfnP5I9VFfhaGXVVE2NUyZpBBXns/JI+x6V9RY2Tw2QmxRJkhh7174EkRazUntIwjMVY9bFG60Lw=="
            )
        )
        response = self._post_synced_credential()
        self.assertEqual(response.status_code, 200)
        self.assertStageResponse(
            response,
            flow=self.flow,
            component="ak-stage-authenticator-webauthn",
            response_errors={
                "response": [
                    {
                        "string": (
                            "This authenticator type is not allowed because it can be "
                            "backed up or synced to other devices (for example via a "
                            "cloud keychain or password manager). Please use a "
                            "hardware-bound authenticator, such as a security key or a "
                            "device's built-in biometric/PIN authenticator without cloud "
                            "sync enabled, or contact your authentik administrator for "
                            "help."
                        ),
                        "code": "invalid",
                    }
                ]
            },
        )
        self.assertFalse(WebAuthnDevice.objects.filter(user=self.user).exists())

    def _post_synced_credential(self):
        return self.client.post(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
            data={
                "component": "ak-stage-authenticator-webauthn",
                "response": {
                    "id": "kqnmrVLnDG-OwsSNHkihYZaNz5s",
                    "rawId": "kqnmrVLnDG-OwsSNHkihYZaNz5s",
                    "type": "public-key",
                    "registrationClientExtensions": "{}",
                    "response": {
                        "clientDataJSON": (
                            "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmd"
                            "lIjoiMDNYb2RpNTRnS3NmblA1STlWRmZoYUdYVlZFMk5VeV"
                            "pwQkJYbnNfSkkteDZWOVJZMlR3MlFteFJKa2hoNzE3NEVrU"
                            "mF6VW50SXdqTVZZOWJGRzYwTHciLCJvcmlnaW4iOiJodHRw"
                            "Oi8vbG9jYWxob3N0OjkwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
                        ),
                        "attestationObject": (
                            "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5Yg"
                            "OjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAPv8MA"
                            "cVTk7MjAtuAgVX170AFJKp5q1S5wxvjsLEjR5IoWGWjc-bp"
                            "QECAyYgASFYIKtcZHPumH37XHs0IM1v3pUBRIqHVV_SE-Lq"
                            "2zpJAOVXIlgg74Fg_WdB0kuLYqCKbxogkEPaVtR_iR3IyQFIJAXBzds"
                        ),
                    },
                },
            },
            SERVER_NAME="localhost",
            SERVER_PORT="9000",
        )

    def _prepare_plan(self, challenge: bytes):
        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        plan.context[PLAN_CONTEXT_PENDING_USER] = self.user
        plan.context[PLAN_CONTEXT_WEBAUTHN_CHALLENGE] = challenge
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()

    def test_register_backup_denied_allows_device_bound(self):
        """backup_eligibility=denied allows a single-device (BE=0) credential"""
        self.stage.backup_eligibility = CredentialBackupEligibility.DENIED
        self.stage.save()
        self._prepare_plan(
            b64decode(
                b"iHIX3AtkZZCxSYLxOhk80ZXI7RnAC0Pb4WTk9dEJ4eLJdzoh8jRmjKW2U9oE/CBn5n6Zj67BIIZvFL3lpiwJwg=="
            )
        )
        response = self.client.post(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
            data={
                "component": "ak-stage-authenticator-webauthn",
                "response": loads(load_fixture("fixtures/register.json")),
            },
            SERVER_NAME="localhost",
            SERVER_PORT="9000",
        )
        self.assertEqual(response.status_code, 200)
        self.assertStageRedirects(response, reverse("authentik_core:root-redirect"))
        device = WebAuthnDevice.objects.filter(user=self.user).first()
        self.assertIsNotNone(device)
        self.assertFalse(device.credential_backup_eligible)
        self.assertFalse(device.credential_backed_up)

    def test_register_backup_denied_rejects_synced(self):
        """backup_eligibility=denied rejects a multi-device (BE=1) credential"""
        self.stage.backup_eligibility = CredentialBackupEligibility.DENIED
        self.stage.save()
        self._prepare_plan(
            b64decode(
                b"03Xodi54gKsfnP5I9VFfhaGXVVE2NUyZpBBXns/JI+x6V9RY2Tw2QmxRJkhh7174EkRazUntIwjMVY9bFG60Lw=="
            )
        )
        response = self._post_synced_credential()
        self.assertEqual(response.status_code, 200)
        self.assertStageResponse(
            response,
            flow=self.flow,
            component="ak-stage-authenticator-webauthn",
            response_errors={
                "response": [
                    {
                        "string": (
                            "This authenticator type is not allowed because it can be "
                            "backed up or synced to other devices (for example via a "
                            "cloud keychain or password manager). Please use a "
                            "hardware-bound authenticator, such as a security key or a "
                            "device's built-in biometric/PIN authenticator without cloud "
                            "sync enabled, or contact your authentik administrator for "
                            "help."
                        ),
                        "code": "invalid",
                    }
                ]
            },
        )
        self.assertFalse(WebAuthnDevice.objects.filter(user=self.user).exists())

    def test_register_backup_required_allows_synced(self):
        """backup_eligibility=required allows a multi-device (BE=1) credential"""
        self.stage.backup_eligibility = CredentialBackupEligibility.REQUIRED
        self.stage.save()
        self._prepare_plan(
            b64decode(
                b"03Xodi54gKsfnP5I9VFfhaGXVVE2NUyZpBBXns/JI+x6V9RY2Tw2QmxRJkhh7174EkRazUntIwjMVY9bFG60Lw=="
            )
        )
        response = self._post_synced_credential()
        self.assertEqual(response.status_code, 200)
        self.assertStageRedirects(response, reverse("authentik_core:root-redirect"))
        device = WebAuthnDevice.objects.filter(user=self.user).first()
        self.assertIsNotNone(device)
        self.assertTrue(device.credential_backup_eligible)
        self.assertTrue(device.credential_backed_up)

    def test_register_backup_required_rejects_device_bound(self):
        """backup_eligibility=required rejects a single-device (BE=0) credential"""
        self.stage.backup_eligibility = CredentialBackupEligibility.REQUIRED
        self.stage.save()
        self._prepare_plan(
            b64decode(
                b"iHIX3AtkZZCxSYLxOhk80ZXI7RnAC0Pb4WTk9dEJ4eLJdzoh8jRmjKW2U9oE/CBn5n6Zj67BIIZvFL3lpiwJwg=="
            )
        )
        response = self.client.post(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
            data={
                "component": "ak-stage-authenticator-webauthn",
                "response": loads(load_fixture("fixtures/register.json")),
            },
            SERVER_NAME="localhost",
            SERVER_PORT="9000",
        )
        self.assertEqual(response.status_code, 200)
        self.assertStageResponse(
            response,
            flow=self.flow,
            component="ak-stage-authenticator-webauthn",
            response_errors={
                "response": [
                    {
                        "string": (
                            "This authenticator cannot be backed up or synced. Please use "
                            "a passkey that can be synced across devices, or contact your "
                            "authentik administrator for help."
                        ),
                        "code": "invalid",
                    }
                ]
            },
        )
        self.assertFalse(WebAuthnDevice.objects.filter(user=self.user).exists())

    # --- Attestation requirement ---

    def _post_credential(self, credential: dict):
        return self.client.post(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
            data={"component": "ak-stage-authenticator-webauthn", "response": credential},
            SERVER_NAME="localhost",
            SERVER_PORT="9000",
        )

    def _assert_registration_error(self, response, message: str):
        self.assertEqual(response.status_code, 200)
        self.assertStageResponse(
            response,
            flow=self.flow,
            component="ak-stage-authenticator-webauthn",
            response_errors={"response": [{"string": message, "code": "invalid"}]},
        )
        self.assertFalse(WebAuthnDevice.objects.filter(user=self.user).exists())

    def test_register_attestation_not_required_default(self):
        """Default (not_required): a self-consistent credential registers without any trust
        anchor being known for its AAGUID (historical behavior)"""
        root_key, _root_pem = generate_test_root_ca()
        challenge, aaguid = os.urandom(32), os.urandom(16)
        self._prepare_plan(challenge)
        response = self._post_credential(
            build_synthetic_packed_attestation(aaguid, challenge, root_key)
        )
        self.assertStageRedirects(response, reverse("authentik_core:root-redirect"))
        self.assertTrue(WebAuthnDevice.objects.filter(user=self.user).exists())

    def test_register_attestation_required_unknown_device_type(self):
        """required: reject when the AAGUID has no known device type (no trust anchor)"""
        self.stage.attestation_requirement = AttestationRequirement.REQUIRED
        self.stage.save()
        root_key, _root_pem = generate_test_root_ca()
        challenge, aaguid = os.urandom(32), os.urandom(16)
        self._prepare_plan(challenge)
        response = self._post_credential(
            build_synthetic_packed_attestation(aaguid, challenge, root_key)
        )
        self._assert_registration_error(
            response,
            (
                "This authenticator's security level could not be verified. Please use a "
                "different authenticator, or contact your authentik administrator for help."
            ),
        )

    def test_register_attestation_required_no_roots(self):
        """required: reject when the device type is known but has no trust anchors"""
        self.stage.attestation_requirement = AttestationRequirement.REQUIRED
        self.stage.save()
        root_key, _root_pem = generate_test_root_ca()
        challenge, aaguid = os.urandom(32), os.urandom(16)
        WebAuthnDeviceType.objects.create(aaguid=UUID(bytes=aaguid), description="No roots")
        self._prepare_plan(challenge)
        response = self._post_credential(
            build_synthetic_packed_attestation(aaguid, challenge, root_key)
        )
        self._assert_registration_error(
            response,
            (
                "This authenticator's security level could not be verified. Please use a "
                "different authenticator, or contact your authentik administrator for help."
            ),
        )

    def test_register_attestation_required_chain_valid(self):
        """required: accept when the chain validates against the AAGUID's stored root"""
        self.stage.attestation_requirement = AttestationRequirement.REQUIRED
        self.stage.save()
        root_key, root_pem = generate_test_root_ca()
        challenge, aaguid = os.urandom(32), os.urandom(16)
        WebAuthnDeviceType.objects.create(
            aaguid=UUID(bytes=aaguid),
            description="Attestable",
            attestation_root_certificates=[root_pem],
        )
        self._prepare_plan(challenge)
        response = self._post_credential(
            build_synthetic_packed_attestation(aaguid, challenge, root_key)
        )
        self.assertStageRedirects(response, reverse("authentik_core:root-redirect"))
        self.assertTrue(WebAuthnDevice.objects.filter(user=self.user).exists())

    def test_register_attestation_required_chain_invalid(self):
        """required: reject when the leaf was NOT issued by the root stored for the claimed
        AAGUID (i.e. a spoofed AAGUID claim, signed by some other CA)"""
        self.stage.attestation_requirement = AttestationRequirement.REQUIRED
        self.stage.save()
        attacker_key, _attacker_pem = generate_test_root_ca()
        _real_key, real_pem = generate_test_root_ca()
        challenge, aaguid = os.urandom(32), os.urandom(16)
        WebAuthnDeviceType.objects.create(
            aaguid=UUID(bytes=aaguid),
            description="Attestable",
            attestation_root_certificates=[real_pem],
        )
        self._prepare_plan(challenge)
        response = self._post_credential(
            build_synthetic_packed_attestation(aaguid, challenge, attacker_key)
        )
        self._assert_registration_error(
            response,
            (
                "This authenticator's attestation could not be verified against a trusted "
                "certificate. Contact your authentik administrator for help."
            ),
        )

    def test_register_attestation_required_none_format(self):
        """required: reject credentials that carry no attestation statement ("none")"""
        self.stage.attestation_requirement = AttestationRequirement.REQUIRED
        self.stage.save()
        credential = loads(load_fixture("fixtures/register.json"))
        raw = credential["response"]["attestationObject"]
        att_obj = parse_cbor(urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        credential["response"]["attestationObject"] = b64url(
            encode_cbor({"fmt": "none", "attStmt": {}, "authData": att_obj["authData"]})
        )
        self._prepare_plan(
            b64decode(
                b"iHIX3AtkZZCxSYLxOhk80ZXI7RnAC0Pb4WTk9dEJ4eLJdzoh8jRmjKW2U9oE/CBn5n6Zj67BIIZvFL3lpiwJwg=="
            )
        )
        response = self._post_credential(credential)
        self._assert_registration_error(
            response,
            (
                "This authenticator's security level could not be verified. Please use a "
                "different authenticator, or contact your authentik administrator for help."
            ),
        )

    # --- Key protection ---

    KEY_PROTECTION_ERROR = (
        "This authenticator does not meet the required key protection level. Please use a "
        "different authenticator, or contact your authentik administrator for help."
    )

    def _register_with_key_protection(
        self,
        selected: list[str],
        declared: list[str],
        mode: str = KeyProtectionMatchMode.ANY,
        attestation_requirement: str = AttestationRequirement.REQUIRED,
    ):
        """Configure the stage, register a device type declaring `declared` key protection
        with a valid trust anchor, and post a correctly attested credential for it."""
        self.stage.attestation_requirement = attestation_requirement
        self.stage.key_protection_types = selected
        self.stage.key_protection_match_mode = mode
        self.stage.save()
        root_key, root_pem = generate_test_root_ca()
        challenge, aaguid = os.urandom(32), os.urandom(16)
        WebAuthnDeviceType.objects.create(
            aaguid=UUID(bytes=aaguid),
            description="Key protection test device",
            attestation_root_certificates=[root_pem],
            key_protection=declared,
        )
        self._prepare_plan(challenge)
        return self._post_credential(
            build_synthetic_packed_attestation(aaguid, challenge, root_key)
        )

    def test_key_protection_any_match(self):
        """any: one declared type being accepted is enough"""
        response = self._register_with_key_protection(
            ["secure_element", "tee"], ["hardware", "secure_element"]
        )
        self.assertStageRedirects(response, reverse("authentik_core:root-redirect"))
        self.assertTrue(WebAuthnDevice.objects.filter(user=self.user).exists())

    def test_key_protection_any_no_match(self):
        """any: reject when none of the declared types is accepted"""
        response = self._register_with_key_protection(["tee"], ["hardware", "secure_element"])
        self._assert_registration_error(response, self.KEY_PROTECTION_ERROR)

    def test_key_protection_any_tolerates_unaccepted_extra_type(self):
        """any (documented weakness): a model declaring an accepted type next to an
        unaccepted one (here software) still passes. Use `all` to exclude such models."""
        response = self._register_with_key_protection(["hardware"], ["hardware", "software"])
        self.assertStageRedirects(response, reverse("authentik_core:root-redirect"))
        self.assertTrue(WebAuthnDevice.objects.filter(user=self.user).exists())

    def test_key_protection_all_match(self):
        """all: accept when every declared type is accepted"""
        response = self._register_with_key_protection(
            ["hardware", "secure_element", "remote_handle"],
            ["hardware", "secure_element", "remote_handle"],
            mode=KeyProtectionMatchMode.ALL,
        )
        self.assertStageRedirects(response, reverse("authentik_core:root-redirect"))
        self.assertTrue(WebAuthnDevice.objects.filter(user=self.user).exists())

    def test_key_protection_all_extra_accepted_types_are_fine(self):
        """all: the accepted list may be broader than what the model declares"""
        response = self._register_with_key_protection(
            ["hardware", "secure_element", "tee"],
            ["hardware", "secure_element"],
            mode=KeyProtectionMatchMode.ALL,
        )
        self.assertStageRedirects(response, reverse("authentik_core:root-redirect"))
        self.assertTrue(WebAuthnDevice.objects.filter(user=self.user).exists())

    def test_key_protection_all_rejects_unaccepted_declared_type(self):
        """all: reject when the model declares a type outside the accepted list"""
        response = self._register_with_key_protection(
            ["hardware", "secure_element"],
            ["hardware", "tee"],
            mode=KeyProtectionMatchMode.ALL,
        )
        self._assert_registration_error(response, self.KEY_PROTECTION_ERROR)

    def test_key_protection_all_rejects_software_mix(self):
        """all: a model mixing software with hardware types is rejected when software is
        not accepted, which is the point of using `all` for "hardware keys only" """
        response = self._register_with_key_protection(
            ["hardware", "secure_element", "tee", "remote_handle"],
            ["hardware", "software"],
            mode=KeyProtectionMatchMode.ALL,
        )
        self._assert_registration_error(response, self.KEY_PROTECTION_ERROR)

    def test_key_protection_all_rejects_software_remote_handle(self):
        """all: software + remote_handle is rejected although remote_handle is accepted"""
        response = self._register_with_key_protection(
            ["hardware", "secure_element", "tee", "remote_handle"],
            ["software", "remote_handle"],
            mode=KeyProtectionMatchMode.ALL,
        )
        self._assert_registration_error(response, self.KEY_PROTECTION_ERROR)

    def test_key_protection_all_empty_declaration(self):
        """all: a model declaring nothing must not pass the subset test vacuously"""
        response = self._register_with_key_protection(
            ["hardware"], [], mode=KeyProtectionMatchMode.ALL
        )
        self._assert_registration_error(response, self.KEY_PROTECTION_ERROR)

    def test_key_protection_software_only_device(self):
        """a software-only authenticator does not satisfy a hardware requirement"""
        response = self._register_with_key_protection(["hardware"], ["software"])
        self._assert_registration_error(response, self.KEY_PROTECTION_ERROR)

    def test_key_protection_device_without_metadata(self):
        """a device type that declares no key protection satisfies no selection"""
        response = self._register_with_key_protection(["hardware"], [])
        self._assert_registration_error(response, self.KEY_PROTECTION_ERROR)

    def test_key_protection_implies_attestation(self):
        """Even if the stage was saved without going through the API validation (so
        attestation_requirement is not_required), key protection still forces attestation:
        an unattestable device is rejected instead of its self-reported AAGUID being trusted"""
        self.stage.attestation_requirement = AttestationRequirement.NOT_REQUIRED
        self.stage.key_protection_types = ["hardware"]
        self.stage.save()
        root_key, _root_pem = generate_test_root_ca()
        challenge, aaguid = os.urandom(32), os.urandom(16)
        # Device type claims hardware protection but has no trust anchor to prove it
        WebAuthnDeviceType.objects.create(
            aaguid=UUID(bytes=aaguid), description="Claimed", key_protection=["hardware"]
        )
        self._prepare_plan(challenge)
        response = self._post_credential(
            build_synthetic_packed_attestation(aaguid, challenge, root_key)
        )
        self._assert_registration_error(
            response,
            (
                "This authenticator's security level could not be verified. Please use a "
                "different authenticator, or contact your authentik administrator for help."
            ),
        )

    def test_key_protection_spoofed_aaguid(self):
        """A device claiming the AAGUID of a hardware-protected model, but attested by a
        different CA, is rejected"""
        self.stage.attestation_requirement = AttestationRequirement.REQUIRED
        self.stage.key_protection_types = ["secure_element"]
        self.stage.save()
        attacker_key, _attacker_pem = generate_test_root_ca()
        _vendor_key, vendor_pem = generate_test_root_ca()
        challenge, aaguid = os.urandom(32), os.urandom(16)
        WebAuthnDeviceType.objects.create(
            aaguid=UUID(bytes=aaguid),
            description="Secure vendor key",
            attestation_root_certificates=[vendor_pem],
            key_protection=["hardware", "secure_element"],
        )
        self._prepare_plan(challenge)
        response = self._post_credential(
            build_synthetic_packed_attestation(aaguid, challenge, attacker_key)
        )
        self._assert_registration_error(
            response,
            (
                "This authenticator's attestation could not be verified against a trusted "
                "certificate. Contact your authentik administrator for help."
            ),
        )

    def test_api_key_protection_requires_attestation(self):
        """The API refuses key protection restrictions without required attestation"""
        self.client.force_login(self.user)
        url = reverse("authentik_api:authenticatorwebauthnstage-list")
        response = self.client.post(
            url,
            data={"name": generate_id(), "key_protection_types": ["hardware"]},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("attestation_requirement", response.json())
        response = self.client.post(
            url,
            data={
                "name": generate_id(),
                "key_protection_types": ["hardware"],
                "attestation_requirement": "required",
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201)

    def test_api_key_protection_partial_update(self):
        """Lowering attestation to not_required on a stage with key protection is refused,
        and so is adding key protection to a stage that does not require attestation"""
        self.client.force_login(self.user)
        detail = reverse(
            "authentik_api:authenticatorwebauthnstage-detail", kwargs={"pk": self.stage.pk}
        )
        response = self.client.patch(
            detail, data={"key_protection_types": ["tee"]}, content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        self.stage.attestation_requirement = AttestationRequirement.REQUIRED
        self.stage.key_protection_types = ["tee"]
        self.stage.save()
        response = self.client.patch(
            detail,
            data={"attestation_requirement": "not_required"},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
