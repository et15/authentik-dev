"""WebAuthn stage"""

from base64 import urlsafe_b64decode
from dataclasses import dataclass
from uuid import UUID

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import load_der_x509_certificate
from django.http import HttpRequest, HttpResponse
from django.http.request import QueryDict
from django.utils.translation import gettext as __
from django.utils.translation import gettext_lazy as _
from rest_framework.fields import CharField
from rest_framework.serializers import ValidationError
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.options_to_json_dict import options_to_json_dict
from webauthn.helpers.parse_attestation_object import parse_attestation_object
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AttestationFormat,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    CredentialDeviceType,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialHint,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.registration.generate_registration_options import generate_registration_options
from webauthn.registration.verify_registration_response import (
    VerifiedRegistration,
    verify_registration_response,
)

from authentik.core.api.utils import JSONDictField
from authentik.core.models import User
from authentik.crypto.models import fingerprint_sha256
from authentik.flows.challenge import (
    Challenge,
    ChallengeResponse,
    WithUserInfoChallenge,
)
from authentik.flows.stage import ChallengeStageView
from authentik.stages.authenticator_webauthn.models import (
    UNKNOWN_DEVICE_TYPE_AAGUID,
    AttestationRequirement,
    AuthenticatorWebAuthnStage,
    CredentialBackupEligibility,
    KeyProtectionMatchMode,
    WebAuthnDevice,
    WebAuthnDeviceType,
)
from authentik.stages.authenticator_webauthn.utils import get_origin, get_rp_id

PLAN_CONTEXT_WEBAUTHN_CHALLENGE = "goauthentik.io/stages/authenticator_webauthn/challenge"
PLAN_CONTEXT_WEBAUTHN_ATTEMPT = "goauthentik.io/stages/authenticator_webauthn/attempt"


# Attestation formats for which webauthn validates the certificate chain exclusively against
# the roots passed via `pem_root_certs_bytes_by_fmt`. All others cannot prove the claimed AAGUID:
# "none" carries no proof, "fido-u2f" has no AAGUID, and "apple", "android-key" and
# "android-safetynet" add roots of their own, so a valid Apple/Google chain would be accepted
# for any claimed AAGUID.
ROOT_VALIDATED_ATTESTATION_FORMATS = (AttestationFormat.PACKED, AttestationFormat.TPM)


@dataclass
class VerifiedRegistrationData:
    registration: VerifiedRegistration
    attest_cert: str | None = None
    attest_cert_fingerprint: str | None = None
    # True only if the credential's attestation statement was successfully validated against
    # a trusted manufacturer root certificate stored for its claimed AAGUID. Anything that
    # wants to rely on AAGUID-derived metadata (e.g. WebAuthnDeviceType.key_protection) as a
    # security signal rather than a display hint must check this first.
    attestation_trusted: bool = False


class AuthenticatorWebAuthnChallenge(WithUserInfoChallenge):
    """WebAuthn Challenge"""

    registration = JSONDictField()
    component = CharField(default="ak-stage-authenticator-webauthn")


class AuthenticatorWebAuthnChallengeResponse(ChallengeResponse):
    """WebAuthn Challenge response"""

    response = JSONDictField()
    component = CharField(default="ak-stage-authenticator-webauthn")

    request: HttpRequest
    user: User

    def _get_pre_attestation(self, response: dict):
        """Parse the raw, not-yet-verified attestationObject to read its format and claimed
        AAGUID *before* calling verify_registration_response, so the right per-AAGUID trust
        anchors can be supplied to that call. Verifies nothing by itself."""
        inner = response.get("response")
        raw_attestation_object = inner.get("attestationObject") if isinstance(inner, dict) else None
        if not raw_attestation_object or not isinstance(raw_attestation_object, str):
            return None
        padded = raw_attestation_object + "=" * (-len(raw_attestation_object) % 4)
        try:
            return parse_attestation_object(urlsafe_b64decode(padded))
        except WebAuthnException, ValueError:
            return None

    def _trusted_roots_for_attestation(
        self, response: dict
    ) -> dict[AttestationFormat, list[bytes]]:
        """Resolve the trusted root certificates (PEM bytes) that this registration's
        attestation chain must validate against, based on the claimed AAGUID's FIDO MDS
        entry. Raises ValidationError if attestation cannot be satisfied at all (no
        attestation given, unknown AAGUID, or no trust anchor available for it)."""
        unverifiable_error = ValidationError(
            _(
                "This authenticator's security level could not be verified. Please use a "
                "different authenticator, or contact your {brand} administrator for "
                "help.".format(brand=self.stage.request.brand.branding_title)
            )
        )
        pre_att_obj = self._get_pre_attestation(response)
        if pre_att_obj is None or pre_att_obj.fmt not in ROOT_VALIDATED_ATTESTATION_FORMATS:
            raise unverifiable_error
        # Without a certificate chain there is nothing to validate against the roots. For
        # "packed" the library treats a statement without x5c as self attestation (signed
        # with the credential's own key) and skips the chain validation entirely.
        if not pre_att_obj.att_stmt or not pre_att_obj.att_stmt.x5c:
            raise unverifiable_error
        attested = pre_att_obj.auth_data.attested_credential_data
        if not attested or not attested.aaguid:
            raise unverifiable_error
        device_type = WebAuthnDeviceType.objects.filter(aaguid=UUID(bytes=attested.aaguid)).first()
        if not device_type or not device_type.attestation_root_certificates:
            raise unverifiable_error
        return {
            AttestationFormat(pre_att_obj.fmt): [
                pem.encode("utf-8") for pem in device_type.attestation_root_certificates
            ]
        }

    def _attestation_enforced(self, stage: AuthenticatorWebAuthnStage) -> bool:
        """Whether attestation chain validation must be performed for this stage. Key
        protection restrictions imply it: `keyProtection` comes from the metadata entry of
        the claimed AAGUID, which is only trustworthy once attestation has been verified.
        This also holds if the stage was configured without going through the API
        validation."""
        return stage.attestation_requirement == AttestationRequirement.REQUIRED or bool(
            stage.key_protection_types
        )

    def validate_response(self, response: dict) -> VerifiedRegistrationData:
        """Validate webauthn challenge response"""
        challenge = self.stage.executor.plan.context[PLAN_CONTEXT_WEBAUTHN_CHALLENGE]
        stage: AuthenticatorWebAuthnStage = self.stage.executor.current_stage

        pem_root_certs_bytes_by_fmt = None
        if self._attestation_enforced(stage):
            # Raises ValidationError itself if attestation can't be satisfied
            pem_root_certs_bytes_by_fmt = self._trusted_roots_for_attestation(response)

        try:
            registration: VerifiedRegistration = verify_registration_response(
                credential=response,
                expected_challenge=challenge,
                expected_rp_id=get_rp_id(self.request),
                expected_origin=get_origin(self.request),
                pem_root_certs_bytes_by_fmt=pem_root_certs_bytes_by_fmt,
            )
        except WebAuthnException as exc:
            self.stage.logger.warning("registration failed", exc=exc)
            if pem_root_certs_bytes_by_fmt:
                raise ValidationError(
                    _(
                        "This authenticator's attestation could not be verified against a "
                        "trusted certificate. Contact your {brand} administrator for "
                        "help.".format(brand=self.stage.request.brand.branding_title)
                    )
                ) from None
            raise ValidationError(
                "Registration failed. Please contact your administrator."
            ) from None

        registration_data = VerifiedRegistrationData(
            registration, attestation_trusted=bool(pem_root_certs_bytes_by_fmt)
        )

        att_obj = parse_attestation_object(registration.attestation_object)
        if (
            att_obj
            and att_obj.att_stmt
            and att_obj.att_stmt.x5c is not None
            and len(att_obj.att_stmt.x5c) > 0
        ):
            cert = load_der_x509_certificate(att_obj.att_stmt.x5c[0])
            registration_data.attest_cert = cert.public_bytes(
                encoding=Encoding.PEM,
            ).decode("utf-8")
            registration_data.attest_cert_fingerprint = fingerprint_sha256(cert)

        if WebAuthnDevice.objects.filter(
            credential_id=bytes_to_base64url(registration.credential_id)
        ).exists():
            raise ValidationError("Credential ID already exists.")

        aaguid = registration.aaguid
        allowed_aaguids = stage.device_type_restrictions.values_list("aaguid", flat=True)
        if allowed_aaguids.exists():
            invalid_error = ValidationError(
                _(
                    "Invalid device type. Contact your {brand} administrator for help.".format(
                        brand=self.stage.request.brand.branding_title
                    )
                )
            )
            # If there are any restrictions set and we didn't get an aaguid, invalid
            if not aaguid:
                raise invalid_error
            # If one of the restrictions is the "special" unknown device type UUID and we
            # don't have a device type for the given aaguid, the device type check passes.
            # This must not return early: the checks below (backup eligibility, ...) still
            # have to be applied to such devices.
            unknown_device_allowed = (
                UUID(UNKNOWN_DEVICE_TYPE_AAGUID) in allowed_aaguids
                and not WebAuthnDeviceType.objects.filter(aaguid=aaguid).exists()
            )
            # Otherwise just check if the given aaguid is in the allowed aaguids
            if not unknown_device_allowed and UUID(aaguid) not in allowed_aaguids:
                raise invalid_error

        if stage.backup_eligibility != CredentialBackupEligibility.ANY:
            # The Backup Eligibility (BE) flag is set by the authenticator at credential
            # creation time and is permanent for the credential's lifetime. It indicates
            # whether the credential *can* be backed up/synced across devices (a "multi
            # device credential", e.g. a passkey in a cloud keychain or password manager)
            # as opposed to being bound to a single piece of hardware (a "single device
            # credential", e.g. a security key or a platform authenticator that hasn't
            # been enrolled with a syncing passkey provider).
            # https://w3c.github.io/webauthn/#sctn-credential-backup
            is_backup_eligible = (
                registration.credential_device_type == CredentialDeviceType.MULTI_DEVICE
            )
            if (
                stage.backup_eligibility == CredentialBackupEligibility.REQUIRED
                and not is_backup_eligible
            ):
                raise ValidationError(
                    _(
                        "This authenticator cannot be backed up or synced. Please use a "
                        "passkey that can be synced across devices, or contact your "
                        "{brand} administrator for help.".format(
                            brand=self.stage.request.brand.branding_title
                        )
                    )
                )
            if (
                stage.backup_eligibility == CredentialBackupEligibility.DENIED
                and is_backup_eligible
            ):
                raise ValidationError(
                    _(
                        "This authenticator type is not allowed because it can be backed "
                        "up or synced to other devices (for example via a cloud keychain "
                        "or password manager). Please use a hardware-bound authenticator, "
                        "such as a security key or a device's built-in biometric/PIN "
                        "authenticator without cloud sync enabled, or contact your "
                        "{brand} administrator for help.".format(
                            brand=self.stage.request.brand.branding_title
                        )
                    )
                )

        if stage.key_protection_types:
            self._check_key_protection(stage, registration_data)
        return registration_data

    def _check_key_protection(
        self, stage: AuthenticatorWebAuthnStage, registration_data: VerifiedRegistrationData
    ) -> None:
        """Check the `keyProtection` types published for the authenticator model against the
        accepted types selected on the stage:
        - ANY: at least one declared type must be accepted
        - ALL: every declared type must be accepted, so a model that also declares an
          unaccepted type (e.g. `software`) is rejected"""
        not_met_error = ValidationError(
            _(
                "This authenticator does not meet the required key protection level. "
                "Please use a different authenticator, or contact your {brand} "
                "administrator for help.".format(brand=self.stage.request.brand.branding_title)
            )
        )
        # keyProtection is only a security signal if the AAGUID was proven by attestation
        if not registration_data.attestation_trusted:
            raise not_met_error
        device_type = WebAuthnDeviceType.objects.filter(
            aaguid=registration_data.registration.aaguid
        ).first()
        if not device_type:
            raise not_met_error
        declared = set(device_type.key_protection or [])
        selected = set(stage.key_protection_types)
        if stage.key_protection_match_mode == KeyProtectionMatchMode.ALL:
            # An empty declaration must not pass the subset test vacuously
            met = bool(declared) and declared <= selected
        else:
            met = bool(declared & selected)
        if not met:
            raise not_met_error


class AuthenticatorWebAuthnStageView(ChallengeStageView):
    """WebAuthn stage"""

    response_class = AuthenticatorWebAuthnChallengeResponse

    def get_challenge(self, *args, **kwargs) -> Challenge:
        stage: AuthenticatorWebAuthnStage = self.executor.current_stage
        self.executor.plan.context.setdefault(PLAN_CONTEXT_WEBAUTHN_ATTEMPT, 0)
        # clear flow variables prior to starting a new registration
        self.executor.plan.context.pop(PLAN_CONTEXT_WEBAUTHN_CHALLENGE, None)
        user = self.get_pending_user()

        # library accepts none so we store null in the database, but if there is a value
        # set, cast it to string to ensure it's not a django class
        authenticator_attachment = stage.authenticator_attachment
        if authenticator_attachment:
            authenticator_attachment = AuthenticatorAttachment(str(authenticator_attachment))

        hints = [PublicKeyCredentialHint(h) for h in stage.hints] or None

        # For compatibility with older user agents that don't support hints,
        # auto-infer authenticatorAttachment from hints when not explicitly set.
        # https://w3c.github.io/webauthn/#enum-hints
        if hints and not authenticator_attachment:
            hint_values = set(stage.hints)
            cross_platform = {"security-key", "hybrid"}
            platform = {"client-device"}
            if hint_values <= cross_platform:
                authenticator_attachment = AuthenticatorAttachment.CROSS_PLATFORM
            elif hint_values <= platform:
                authenticator_attachment = AuthenticatorAttachment.PLATFORM

        registration_options: PublicKeyCredentialCreationOptions = generate_registration_options(
            rp_id=get_rp_id(self.request),
            rp_name=self.request.brand.branding_title,
            user_id=user.uid.encode("utf-8"),
            user_name=user.username,
            user_display_name=user.name,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement(str(stage.resident_key_requirement)),
                user_verification=UserVerificationRequirement(str(stage.user_verification)),
                authenticator_attachment=authenticator_attachment,
            ),
            attestation=AttestationConveyancePreference.DIRECT,
            hints=hints,
        )

        self.executor.plan.context[PLAN_CONTEXT_WEBAUTHN_CHALLENGE] = registration_options.challenge
        return AuthenticatorWebAuthnChallenge(
            data={
                "registration": options_to_json_dict(registration_options),
            }
        )

    def get_response_instance(self, data: QueryDict) -> AuthenticatorWebAuthnChallengeResponse:
        response: AuthenticatorWebAuthnChallengeResponse = super().get_response_instance(data)
        response.request = self.request
        response.user = self.get_pending_user()
        return response

    def challenge_invalid(self, response):
        stage: AuthenticatorWebAuthnStage = self.executor.current_stage
        self.executor.plan.context.setdefault(PLAN_CONTEXT_WEBAUTHN_ATTEMPT, 0)
        self.executor.plan.context[PLAN_CONTEXT_WEBAUTHN_ATTEMPT] += 1
        if (
            stage.max_attempts > 0
            and self.executor.plan.context[PLAN_CONTEXT_WEBAUTHN_ATTEMPT] >= stage.max_attempts
        ):
            return self.executor.stage_invalid(
                __(
                    "Exceeded maximum attempts. "
                    "Contact your {brand} administrator for help.".format(
                        brand=self.request.brand.branding_title
                    )
                )
            )
        return super().challenge_invalid(response)

    def challenge_valid(self, response: ChallengeResponse) -> HttpResponse:
        # Webauthn Challenge has already been validated
        webauthn_credential: VerifiedRegistrationData = response.validated_data["response"]
        name = "WebAuthn Device"
        device_type = WebAuthnDeviceType.objects.filter(
            aaguid=webauthn_credential.registration.aaguid
        ).first()
        if device_type and device_type.description:
            name = device_type.description
        WebAuthnDevice.objects.create(
            name=name,
            user=self.get_pending_user(),
            public_key=bytes_to_base64url(webauthn_credential.registration.credential_public_key),
            credential_id=bytes_to_base64url(webauthn_credential.registration.credential_id),
            sign_count=webauthn_credential.registration.sign_count,
            rp_id=get_rp_id(self.request),
            device_type=device_type,
            aaguid=webauthn_credential.registration.aaguid,
            attestation_certificate_pem=webauthn_credential.attest_cert,
            attestation_certificate_fingerprint=webauthn_credential.attest_cert_fingerprint,
            credential_backup_eligible=(
                webauthn_credential.registration.credential_device_type
                == CredentialDeviceType.MULTI_DEVICE
            ),
            credential_backed_up=webauthn_credential.registration.credential_backed_up,
        )
        return self.executor.stage_ok()
