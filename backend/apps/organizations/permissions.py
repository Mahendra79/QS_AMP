from rest_framework.permissions import SAFE_METHODS, BasePermission

from .models import ADMIN_ROLES, WRITE_ROLES, OrganizationMembership


def resolve_membership(request):
    """Resolve the active organization membership for the request (cached).

    The X-Organization header may select among the user's organizations; a
    user can never select an organization they are not a member of.
    """
    if hasattr(request, "_membership"):
        return request._membership
    membership = None
    user = request.user
    if user and user.is_authenticated:
        qs = OrganizationMembership.objects.select_related("organization").filter(user=user)
        org_id = request.headers.get("X-Organization")
        if org_id:
            try:
                membership = qs.filter(organization_id=org_id).first()
            except Exception:  # malformed uuid
                membership = None
        if membership is None:
            membership = qs.first()
    request._membership = membership
    return membership


class RolePermission(BasePermission):
    """Authenticated org member. Safe methods: any role. Writes: view.write_roles
    (default owner/admin/analyst/developer). Views may set read_roles too."""
    message = "You do not have permission to perform this action."

    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        membership = resolve_membership(request)
        if membership is None:
            self.message = "No organization membership for this user."
            return False
        request.org = membership.organization
        request.role = membership.role
        if request.method in SAFE_METHODS:
            roles = getattr(view, "read_roles", None)
        else:
            action = getattr(view, "action", None)
            per_action = getattr(view, "action_roles", {}) or {}
            roles = per_action.get(action) or getattr(view, "write_roles", WRITE_ROLES)
        return roles is None or membership.role in roles


class AdminOnly(RolePermission):
    def has_permission(self, request, view):
        view.write_roles = ADMIN_ROLES
        view.read_roles = ADMIN_ROLES
        return super().has_permission(request, view)
