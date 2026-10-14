# Generated manually for BE/BS (backup eligibility) enforcement

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        (
            "authentik_stages_authenticator_webauthn",
            "0018_remove_authenticatorwebauthnstage_prevent_duplicate_devices",
        ),
    ]

    operations = [
        migrations.AddField(
            model_name="authenticatorwebauthnstage",
            name="backup_eligibility",
            field=models.TextField(
                choices=[
                    ("any", "Any"),
                    ("required", "Required"),
                    ("denied", "Denied"),
                ],
                default="any",
            ),
        ),
        migrations.AddField(
            model_name="webauthndevice",
            name="credential_backup_eligible",
            field=models.BooleanField(default=None, null=True),
        ),
        migrations.AddField(
            model_name="webauthndevice",
            name="credential_backed_up",
            field=models.BooleanField(default=None, null=True),
        ),
    ]
