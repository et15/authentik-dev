"""WebAuthn stage"""

from cryptography.x509 import Certificate, load_pem_x509_certificate
from django.contrib.auth import get_user_model
from django.contrib.postgres.fields.array import ArrayField
from django.db import models
from django.utils.timezone import now
from django.utils.translation import gettext_lazy as _
from django.views import View
from rest_framework.serializers import BaseSerializer, Serializer
from webauthn.helpers.base64url_to_bytes import base64url_to_bytes
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

from authentik.core.types import UserSettingSerializer
from authentik.flows.models import ConfigurableStage, FriendlyNamedStage, Stage
from authentik.lib.models import InternallyManagedMixin, SerializerModel, SimpleThroughModel
from authentik.stages.authenticator.models import Device

UNKNOWN_DEVICE_TYPE_AAGUID = "00000000-0000-0000-0000-000000000000"


class UserVerification(models.TextChoices):
    """The degree to which the Relying Party wishes to verify a user's identity.

    Members:
        `REQUIRED`: User verification must occur
        `PREFERRED`: User verification would be great, but if not that's okay too
        `DISCOURAGED`: User verification should not occur, but it's okay if it does

    https://www.w3.org/TR/webauthn-2/#enumdef-userverificationrequirement
    """

    REQUIRED = "required"
    PREFERRED = "preferred"
    DISCOURAGED = "discouraged"


class ResidentKeyRequirement(models.TextChoices):
    """The Relying Party's preference for the authenticator to create a dedicated "client-side"
    credential for it. Requiring an authenticator to store a dedicated credential should not be
    done lightly due to the limited storage capacity of some types of authenticators.

    Members:
        `DISCOURAGED`: The authenticator should not create a dedicated credential
        `PREFERRED`: The authenticator can create and store a dedicated credential, but if it
            doesn't that's alright too
        `REQUIRED`: The authenticator MUST create a dedicated credential. If it cannot, the RP
            is prepared for an error to occur.

    https://www.w3.org/TR/webauthn-2/#enum-residentKeyRequirement
    """

    DISCOURAGED = "discouraged"
    PREFERRED = "preferred"
    REQUIRED = "required"


class AuthenticatorAttachment(models.TextChoices):
    """How an authenticator is connected to the client/browser.

    Members:
        `PLATFORM`: A non-removable authenticator, like TouchID or Windows Hello
        `CROSS_PLATFORM`: A "roaming" authenticator, like a YubiKey

    https://www.w3.org/TR/webauthn-2/#enumdef-authenticatorattachment
    """

    PLATFORM = "platform"
    CROSS_PLATFORM = "cross-platform"


class CredentialBackupEligibility(models.TextChoices):
    """Policy for whether a WebAuthn credential is allowed to be a "multi-device credential"
    (i.e. one that can be backed up/synced across devices, such as a passkey stored in
    iCloud Keychain, Google Password Manager, or a third-party password manager) versus a
    "single-device credential" that is bound to a single, specific piece of hardware (such
    as a YubiKey, or a platform authenticator like Windows Hello/Touch ID that has not been
    enrolled with a cloud-syncing passkey provider).

    This is determined using the Backup Eligibility (BE) flag of the authenticator data,
    which authenticators set permanently at credential-creation time.

    Members:
        `ANY`: No restriction is applied based on backup eligibility
        `REQUIRED`: Only credentials that are eligible for backup/sync (BE=1) may be
            registered
        `DENIED`: Only credentials that are *not* eligible for backup/sync (BE=0), i.e.
            single-device/hardware-bound credentials, may be registered

    https://w3c.github.io/webauthn/#sctn-credential-backup
    """

    ANY = "any"
    REQUIRED = "required"
    DENIED = "denied"


class WebAuthnHint(models.TextChoices):
    """Hints to guide the browser in prioritizing the preferred authenticator during
    WebAuthn registration and authentication. Unlike authenticatorAttachment, hints are
    advisory and browsers may ignore them.

    Members:
        `SECURITY_KEY`: A portable FIDO2 authenticator, like a YubiKey
        `CLIENT_DEVICE`: The device WebAuthn is being called on, like TouchID or Windows Hello
        `HYBRID`: A platform authenticator on a mobile device, accessed via QR code

    https://w3c.github.io/webauthn/#enumdef-publickeycredentialhint
    """

    SECURITY_KEY = "security-key"
    CLIENT_DEVICE = "client-device"
    HYBRID = "hybrid"


class AttestationRequirement(models.TextChoices):
    """Policy for whether a credential's attestation statement must be cryptographically
    validated against a trusted manufacturer root certificate before registration is
    accepted.

    Attestation ties a credential's claimed AAGUID to a certificate chain rooted in a CA
    that the FIDO Alliance has vetted for that manufacturer. Without this check, an
    authenticator's self-reported AAGUID (and by extension its FIDO Metadata Service entry,
    including `key_protection`) cannot be trusted, since nothing stops a client from
    claiming an arbitrary AAGUID.

    Members:
        `NOT_REQUIRED`: Attestation is not validated. The AAGUID reported by the
            authenticator is used as-is, without cryptographic proof (historical behavior).
        `REQUIRED`: The authenticator must provide a full (non-"none") attestation
            statement, its AAGUID must be a known entry in authentik's FIDO Metadata
            Service data with at least one trusted root certificate, and that certificate
            chain must successfully validate. Registration is rejected otherwise.
    """

    NOT_REQUIRED = "not_required"
    REQUIRED = "required"


class AuthenticatorWebAuthnStage(ConfigurableStage, FriendlyNamedStage, Stage):
    """Setup WebAuthn-based authentication for the user."""

    user_verification = models.TextField(
        choices=UserVerification.choices,
        default=UserVerification.PREFERRED,
    )
    resident_key_requirement = models.TextField(
        choices=ResidentKeyRequirement.choices,
        default=ResidentKeyRequirement.PREFERRED,
    )
    authenticator_attachment = models.TextField(  # noqa: DJ001
        choices=AuthenticatorAttachment.choices, default=None, null=True
    )

    hints = ArrayField(
        models.TextField(choices=WebAuthnHint.choices),
        default=list,
        blank=True,
    )

    device_type_restrictions = models.ManyToManyField(
        "WebAuthnDeviceType", blank=True, through="AuthenticatorWebAuthnStageDeviceTypeRestriction"
    )

    backup_eligibility = models.TextField(
        choices=CredentialBackupEligibility.choices,
        default=CredentialBackupEligibility.ANY,
    )

    attestation_requirement = models.TextField(
        choices=AttestationRequirement.choices,
        default=AttestationRequirement.NOT_REQUIRED,
    )

    max_attempts = models.PositiveIntegerField(default=0)

    @property
    def serializer(self) -> type[BaseSerializer]:
        from authentik.stages.authenticator_webauthn.api.stages import (
            AuthenticatorWebAuthnStageSerializer,
        )

        return AuthenticatorWebAuthnStageSerializer

    @property
    def view(self) -> type[View]:
        from authentik.stages.authenticator_webauthn.stage import AuthenticatorWebAuthnStageView

        return AuthenticatorWebAuthnStageView

    @property
    def component(self) -> str:
        return "ak-stage-authenticator-webauthn-form"

    def ui_user_settings(self) -> UserSettingSerializer | None:
        return UserSettingSerializer(
            data={
                "title": self.friendly_name or str(self._meta.verbose_name),
                "component": "ak-user-settings-authenticator-webauthn",
            }
        )

    def __str__(self) -> str:
        return f"WebAuthn Authenticator Setup Stage {self.name}"

    class Meta:
        verbose_name = _("WebAuthn Authenticator Setup Stage")
        verbose_name_plural = _("WebAuthn Authenticator Setup Stages")


class WebAuthnDevice(SerializerModel, Device):
    """WebAuthn Device for a single user"""

    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)

    name = models.TextField(max_length=200)
    credential_id = models.TextField(unique=True)
    public_key = models.TextField()
    sign_count = models.IntegerField(default=0)
    rp_id = models.CharField(max_length=253)

    created_on = models.DateTimeField(auto_now_add=True)
    last_t = models.DateTimeField(default=now)

    attestation_certificate_pem = models.TextField(null=True, default=None)
    attestation_certificate_fingerprint = models.TextField(null=True, default=None)
    aaguid = models.TextField(default=UNKNOWN_DEVICE_TYPE_AAGUID)
    device_type = models.ForeignKey(
        "WebAuthnDeviceType", on_delete=models.SET_DEFAULT, null=True, default=None
    )

    # Backup Eligibility (BE) flag, captured at registration time. `True` means the
    # authenticator marked this credential as a multi-device/syncable credential (e.g. a
    # passkey stored in a cloud keychain or password manager); `False` means it is bound to
    # a single piece of hardware. `None` for devices registered before this field existed.
    credential_backup_eligible = models.BooleanField(null=True, default=None)
    # Backup State (BS) flag, captured at registration time. Reflects whether the credential
    # was *actually* backed up at that moment. Unlike `credential_backup_eligible`, this can
    # change over the credential's lifetime, but authentik currently only records the value
    # observed at registration.
    credential_backed_up = models.BooleanField(null=True, default=None)

    @property
    def descriptor(self) -> PublicKeyCredentialDescriptor:
        """Get a publickeydescriptor for this device"""
        return PublicKeyCredentialDescriptor(id=base64url_to_bytes(self.credential_id))

    @property
    def attestation_certificate(self) -> Certificate | None:
        if not self.attestation_certificate_pem:
            return None
        return load_pem_x509_certificate(self.attestation_certificate_pem.encode())

    def set_sign_count(self, sign_count: int) -> None:
        """Set the sign_count and update the last_t datetime."""
        self.sign_count = sign_count
        self.last_t = now()
        self.save()

    @property
    def serializer(self) -> Serializer:
        from authentik.stages.authenticator_webauthn.api.devices import WebAuthnDeviceSerializer

        return WebAuthnDeviceSerializer

    def __str__(self):
        return str(self.name) or str(self.user_id)

    class Meta:
        verbose_name = _("WebAuthn Device")
        verbose_name_plural = _("WebAuthn Devices")


class WebAuthnDeviceType(InternallyManagedMixin, SerializerModel):
    """WebAuthn device type, used to restrict which device types are allowed"""

    aaguid = models.UUIDField(primary_key=True, unique=True)

    description = models.TextField()
    icon = models.TextField(null=True)

    # PEM-encoded root certificates from this device's FIDO Metadata Service metadata
    # statement (`attestationRootCertificates`). An authenticator's attestation statement
    # is only considered trustworthy for this AAGUID if its certificate chain validates
    # against one of these roots. Empty for device types without an attestation root (e.g.
    # surrogate/self attestation only) or for entries from the supplementary AAGUID list.
    attestation_root_certificates = models.JSONField(default=list, blank=True)

    @property
    def serializer(self) -> Serializer:
        from authentik.stages.authenticator_webauthn.api.device_types import (
            WebAuthnDeviceTypeSerializer,
        )

        return WebAuthnDeviceTypeSerializer

    class Meta:
        verbose_name = _("WebAuthn Device type")
        verbose_name_plural = _("WebAuthn Device types")

    def __str__(self) -> str:
        return f"WebAuthn device type {self.description} ({self.aaguid})"


class AuthenticatorWebAuthnStageDeviceTypeRestriction(SimpleThroughModel):
    authenticator_webauthn_stage = models.ForeignKey(
        AuthenticatorWebAuthnStage,
        on_delete=models.CASCADE,
        db_column="authenticatorwebauthnstage_id",
    )
    device_type_restriction = models.ForeignKey(
        WebAuthnDeviceType,
        on_delete=models.CASCADE,
        db_column="webauthndevicetype_id",
    )

    class Meta:
        db_table = "authentik_stages_authenticator_webauthn_authenticatorwebaute3a7"
        unique_together = (("authenticator_webauthn_stage", "device_type_restriction"),)
        verbose_name = _("Authenticator WebAuthn Stage Device Type Restriction")
        verbose_name_plural = _("Authenticator WebAuthn Stage Device Type Restrictions")

    def __str__(self):
        return (
            "AuthenticatorWebAuthnStageDeviceTypeRestriction for AuthenticatorWebAuthnStage "
            f"{self.authenticator_webauthn_stage_id} "
            f"and WebAuthnDeviceType {self.device_type_restriction_id}."
        )
