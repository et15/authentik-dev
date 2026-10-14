"""WebAuthnDeviceType API Views"""

from rest_framework.viewsets import ReadOnlyModelViewSet

from authentik.flows.api.stages import StageSerializer
from authentik.stages.authenticator_webauthn.models import WebAuthnDeviceType


class WebAuthnDeviceTypeSerializer(StageSerializer):
    """WebAuthnDeviceType Serializer"""

    class Meta:
        model = WebAuthnDeviceType
        fields = [
            "aaguid",
            "description",
        ]


class WebAuthnDeviceTypeViewSet(ReadOnlyModelViewSet):
    """WebAuthnDeviceType Viewset"""

    queryset = WebAuthnDeviceType.objects.all()
    serializer_class = WebAuthnDeviceTypeSerializer
    # Explicit: "__all__" cannot build filters for the JSON columns holding attestation data
    filterset_fields = ["aaguid", "description", "icon"]
    ordering = ["description"]
    search_fields = ["description", "aaguid"]
