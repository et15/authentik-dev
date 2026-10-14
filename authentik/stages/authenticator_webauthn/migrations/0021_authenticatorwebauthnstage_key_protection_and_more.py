import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        (
            "authentik_stages_authenticator_webauthn",
            "0020_authenticatorwebauthnstage_attestation_requirement_and_more",
        ),
    ]

    operations = [
        migrations.AddField(
            model_name="authenticatorwebauthnstage",
            name="key_protection_types",
            field=django.contrib.postgres.fields.ArrayField(
                base_field=models.TextField(
                    choices=[
                        ("software", "Software"),
                        ("hardware", "Hardware"),
                        ("tee", "Tee"),
                        ("secure_element", "Secure Element"),
                        ("remote_handle", "Remote Handle"),
                    ]
                ),
                blank=True,
                default=list,
                size=None,
            ),
        ),
        migrations.AddField(
            model_name="authenticatorwebauthnstage",
            name="key_protection_match_mode",
            field=models.TextField(
                choices=[("any", "Any"), ("all", "All")],
                default="any",
            ),
        ),
        migrations.AddField(
            model_name="webauthndevicetype",
            name="key_protection",
            field=models.JSONField(blank=True, default=list),
        ),
    ]
