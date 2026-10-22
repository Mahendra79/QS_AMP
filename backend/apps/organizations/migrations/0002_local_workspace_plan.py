from django.db import migrations, models


def correct_plan(apps, schema_editor):
    Organization = apps.get_model("organizations", "Organization")
    Organization.objects.filter(is_demo=False, plan="enterprise-demo").update(plan="local")


class Migration(migrations.Migration):
    dependencies = [("organizations", "0001_initial")]
    operations = [
        migrations.AlterField(model_name="organization", name="plan",
                              field=models.CharField(default="local", max_length=40)),
        migrations.RunPython(correct_plan, migrations.RunPython.noop),
    ]
