"""AuthenticatorWebAuthnStage API Views"""

from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError
from rest_framework.viewsets import ModelViewSet

from authentik.core.api.used_by import UsedByMixin
from authentik.flows.api.stages import StageSerializer
from authentik.stages.authenticator_webauthn.api.device_types import WebAuthnDeviceTypeSerializer
from authentik.stages.authenticator_webauthn.models import (
    AttestationRequirement,
    AuthenticatorWebAuthnStage,
)


class AuthenticatorWebAuthnStageSerializer(StageSerializer):
    """AuthenticatorWebAuthnStage Serializer"""

    device_type_restrictions_obj = WebAuthnDeviceTypeSerializer(
        source="device_type_restrictions", many=True, read_only=True
    )

    def validate(self, attrs: dict) -> dict:
        attrs = super().validate(attrs)
        # On partial updates fall back to the stored values
        current = self.instance
        key_protection_types = attrs.get(
            "key_protection_types", current.key_protection_types if current else []
        )
        attestation_requirement = attrs.get(
            "attestation_requirement",
            current.attestation_requirement if current else AttestationRequirement.NOT_REQUIRED,
        )
        if key_protection_types and attestation_requirement != AttestationRequirement.REQUIRED:
            raise ValidationError(
                {
                    "attestation_requirement": _(
                        "Attestation must be required when restricting key protection, "
                        "as the key protection level of an authenticator can only be "
                        "trusted if its attestation has been verified."
                    )
                }
            )
        return attrs

    class Meta:
        model = AuthenticatorWebAuthnStage
        fields = StageSerializer.Meta.fields + [
            "configure_flow",
            "friendly_name",
            "user_verification",
            "authenticator_attachment",
            "resident_key_requirement",
            "hints",
            "device_type_restrictions",
            "device_type_restrictions_obj",
            "backup_eligibility",
            "attestation_requirement",
            "key_protection_types",
            "key_protection_match_mode",
            "max_attempts",
        ]


class AuthenticatorWebAuthnStageViewSet(UsedByMixin, ModelViewSet):
    """AuthenticatorWebAuthnStage Viewset"""

    queryset = AuthenticatorWebAuthnStage.objects.all()
    serializer_class = AuthenticatorWebAuthnStageSerializer
    filterset_fields = [
        "name",
        "configure_flow",
        "user_verification",
        "authenticator_attachment",
        "resident_key_requirement",
        "device_type_restrictions",
        "backup_eligibility",
        "attestation_requirement",
        "key_protection_match_mode",
        "max_attempts",
    ]
    ordering = ["name"]
    search_fields = ["name"]
