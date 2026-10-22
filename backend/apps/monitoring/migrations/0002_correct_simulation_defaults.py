from django.db import migrations, models


def correct_existing_configs(apps, schema_editor):
    Configuration = apps.get_model("monitoring", "MonitoringConfiguration")
    Configuration.objects.filter(organization__is_demo=False).update(simulated=False)


class Migration(migrations.Migration):
    dependencies = [("monitoring", "0001_initial")]
    operations = [
        migrations.AlterField(model_name="monitoringconfiguration", name="simulated", field=models.BooleanField(default=False)),
        migrations.RunPython(correct_existing_configs, migrations.RunPython.noop),
    ]
