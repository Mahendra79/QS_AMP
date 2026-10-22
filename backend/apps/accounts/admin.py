from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import APIKey, User


@admin.register(User)
class QSUserAdmin(UserAdmin):
    ordering = ("email",)
    list_display = ("email", "full_name", "is_staff")
    fieldsets = ((None, {"fields": ("email", "password")}), ("Profile", {"fields": ("full_name", "mfa_enabled")}),
                 ("Permissions", {"fields": ("is_active", "is_staff", "is_superuser")}))
    add_fieldsets = ((None, {"classes": ("wide",), "fields": ("email", "password1", "password2")}),)
    search_fields = ("email",)


admin.site.register(APIKey)
