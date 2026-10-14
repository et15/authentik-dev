"""MDS Helpers"""

from functools import lru_cache
from json import loads
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import load_der_x509_certificate
from django.core.cache import cache
from django.db.transaction import atomic
from django.utils.translation import gettext_lazy as _
from dramatiq.actor import actor
from fido2.mds3 import MetadataBlobPayloadEntry, filter_revoked, parse_blob

from authentik.stages.authenticator_webauthn.models import (
    UNKNOWN_DEVICE_TYPE_AAGUID,
    WebAuthnDeviceType,
)
from authentik.tasks.middleware import CurrentTask

CACHE_KEY_MDS_NO_PREFIX = "goauthentik.io/stages/authenticator_webauthn/mds_no"
# The import is skipped while the cached blob number matches the bundled blob. Bump this
# whenever the import starts persisting additional data: it changes the cache key, so blobs
# that were already imported by an older version are imported again after an upgrade.
#   1 (unversioned key): description, icon
#   2: + attestation_root_certificates
MDS_IMPORT_VERSION = 2
CACHE_KEY_MDS_NO = f"{CACHE_KEY_MDS_NO_PREFIX}/v{MDS_IMPORT_VERSION}"
AAGUID_BLOB_PATH = Path(__file__).parent / "mds" / "aaguid.json"
MDS_BLOB_PATH = Path(__file__).parent / "mds" / "blob.jwt"
MDS_CA_PATH = Path(__file__).parent / "mds" / "root-r3.crt"


@lru_cache
def mds_ca() -> bytes:
    """Cache MDS Signature CA, GlobalSign Root CA - R3"""
    with open(MDS_CA_PATH, mode="rb") as _raw_root:
        return _raw_root.read()


def _root_certs_as_pem(entry: MetadataBlobPayloadEntry) -> list[str]:
    """Convert an MDS entry's DER-encoded attestation root certificates (if any) to PEM,
    skipping any certificate that fails to parse rather than discarding the whole entry."""
    pem_certs = []
    for der_cert in entry.metadata_statement.attestation_root_certificates or []:
        try:
            cert = load_der_x509_certificate(der_cert)
        except ValueError:
            continue
        pem_certs.append(cert.public_bytes(encoding=Encoding.PEM).decode("utf-8"))
    return pem_certs


@actor(description=_("Background task to import FIDO Alliance MDS blob and AAGUIDs into database."))
def webauthn_mds_import(force=False):
    """Background task to import FIDO Alliance MDS blob and AAGUIDs into database"""
    self = CurrentTask.get_task()
    with open(MDS_BLOB_PATH, mode="rb") as _raw_blob:
        blob = parse_blob(_raw_blob.read(), mds_ca())
    to_create_update = [
        WebAuthnDeviceType(
            aaguid=UNKNOWN_DEVICE_TYPE_AAGUID,
            description="authentik: Unknown devices",
        )
    ]
    to_delete = []

    mds_no = cache.get(CACHE_KEY_MDS_NO)
    if mds_no != blob.no or force:
        for entry in blob.entries:
            aaguid = entry.aaguid
            if not aaguid:
                continue
            if not filter_revoked(entry):
                to_delete.append(str(aaguid))
                continue
            metadata = entry.metadata_statement
            to_create_update.append(
                WebAuthnDeviceType(
                    aaguid=str(aaguid),
                    description=metadata.description,
                    icon=metadata.icon,
                    attestation_root_certificates=_root_certs_as_pem(entry),
                )
            )
    with atomic():
        WebAuthnDeviceType.objects.bulk_create(
            to_create_update,
            update_conflicts=True,
            update_fields=["description", "icon", "attestation_root_certificates"],
            unique_fields=["aaguid"],
        )
        WebAuthnDeviceType.objects.filter(aaguid__in=to_delete).delete()
    if mds_no != blob.no:
        cache.set(CACHE_KEY_MDS_NO, blob.no)

    with open(AAGUID_BLOB_PATH, mode="rb") as _raw_blob:
        entries = loads(_raw_blob.read())
    to_create_update = [
        WebAuthnDeviceType(
            aaguid=str(aaguid), description=details.get("name"), icon=details.get("icon_light")
        )
        for aaguid, details in entries.items()
    ]
    with atomic():
        WebAuthnDeviceType.objects.bulk_create(
            to_create_update,
            update_conflicts=True,
            update_fields=["description", "icon"],
            unique_fields=["aaguid"],
        )

    self.info("Successfully imported FIDO Alliance MDS blobs and AAGUIDs.")
