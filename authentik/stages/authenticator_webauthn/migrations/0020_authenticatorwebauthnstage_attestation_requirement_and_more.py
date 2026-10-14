from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        (
            "authentik_stages_authenticator_webauthn",
            "0019_authenticatorwebauthnstage_backup_eligibility_and_more",
        ),
    ]

    operations = [
        migrations.AddField(
            model_name="authenticatorwebauthnstage",
            name="attestation_requirement",
            field=models.TextField(
                choices=[("not_required", "Not Required"), ("required", "Required")],
                default="not_required",
            ),
        ),
        migrations.AddField(
            model_name="webauthndevicetype",
            name="attestation_root_certificates",
            field=models.JSONField(blank=True, default=list),
        ),
    ]
