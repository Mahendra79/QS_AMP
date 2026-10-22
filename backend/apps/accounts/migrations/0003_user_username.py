import re

from django.db import migrations, models


def populate_usernames(apps, schema_editor):
    User = apps.get_model("accounts", "User")
    used = set()
    for user in User.objects.order_by("date_joined"):
        base = re.sub(r"[^a-z0-9_.-]", "-", user.email.split("@", 1)[0].lower()) or "user"
        candidate, suffix = base, 2
        while candidate in used or User.objects.filter(username=candidate).exclude(pk=user.pk).exists():
            candidate, suffix = f"{base}-{suffix}", suffix + 1
        user.username = candidate
        user.save(update_fields=["username"])
        used.add(candidate)


class Migration(migrations.Migration):
    dependencies = [("accounts", "0002_initial")]
    operations = [
        migrations.AddField(model_name="user", name="username",
                            field=models.CharField(blank=True, max_length=80, null=True, unique=True)),
        migrations.RunPython(populate_usernames, migrations.RunPython.noop),
    ]
