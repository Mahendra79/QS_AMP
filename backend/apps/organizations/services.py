from django.db import transaction
from django.utils.text import slugify

from .defaults import default_settings
from .models import Environment, Organization, OrganizationMembership, Role


@transaction.atomic
def create_organization(name, owner, is_demo=False):
    base = slugify(name)[:60] or "org"
    slug, n = base, 1
    while Organization.objects.filter(slug=slug).exists():
        n += 1
        slug = f"{base}-{n}"
    org = Organization.objects.create(name=name, slug=slug, is_demo=is_demo, settings=default_settings())
    OrganizationMembership.objects.create(organization=org, user=owner, role=Role.OWNER)
    for i, (env, kind) in enumerate([("Production", "production"), ("Staging", "staging"), ("Development", "development")]):
        Environment.objects.create(organization=org, name=env, kind=kind, is_default=(i == 0))
    return org
