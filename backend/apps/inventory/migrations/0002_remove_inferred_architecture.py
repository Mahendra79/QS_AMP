from django.db import migrations


def remove_inferred_nodes(apps, schema_editor):
    Node = apps.get_model("inventory", "ArchitectureNode")
    Node.objects.filter(key__in=["cdn", "waf", "lb", "gateway", "db"]).delete()


class Migration(migrations.Migration):
    dependencies = [("inventory", "0001_initial")]
    operations = [migrations.RunPython(remove_inferred_nodes, migrations.RunPython.noop)]
