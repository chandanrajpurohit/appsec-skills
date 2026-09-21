# Authorization & IDOR / BOLA Prevention in Django

Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization (BOLA) occurs when an application accepts an identifier (e.g. integer primary key or UUID) from the client and retrieves an object without verifying that the requesting user has permission to access or modify that specific record.

---

## 1. The IDOR Vulnerability Pattern

### Vulnerable View
```python
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import Invoice

@login_required
def view_invoice(request, invoice_id):
    # FLAW: Any authenticated user can access ANY other user's invoice
    # simply by incrementing or guessing invoice_id!
    invoice = get_object_or_404(Invoice, id=invoice_id)
    return JsonResponse({"id": invoice.id, "amount": invoice.amount, "user": invoice.user.id})
```

### Secure View: Scoped Queryset
```python
@login_required
def view_invoice(request, invoice_id):
    # SECURE: Query is filtered by the requesting user
    invoice = get_object_or_404(Invoice, id=invoice_id, user=request.user)
    return JsonResponse({"id": invoice.id, "amount": invoice.amount})
```

---

## 2. Multi-Tenant and Organization Scoping

When building SaaS applications where records belong to organizations/tenants:

```python
from django.core.exceptions import PermissionDenied

@login_required
def update_project(request, project_id):
    # 1. Fetch user's active organization memberships
    user_org_ids = request.user.memberships.values_list("organization_id", flat=True)

    # 2. Scope lookup to projects belonging to organizations user has access to
    project = get_object_or_404(Project, id=project_id, organization_id__in=user_org_ids)

    # 3. Verify specific role if editing requires write privileges
    if not request.user.memberships.filter(organization=project.organization, role__in=["admin", "editor"]).exists():
        raise PermissionDenied("You do not have permission to modify projects in this organization.")

    # Proceed with update...
```

---

## 3. Django REST Framework (DRF) IDOR Defense

In DRF `ModelViewSet` and generic views, the primary defense against IDOR is overriding `get_queryset()`.

### Vulnerable ViewSet
```python
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

class OrderViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    # FLAW: Default queryset returns ALL orders in the system!
    queryset = Order.objects.all()
```

### Secure ViewSet: Dynamic Scoped Queryset
```python
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

class OrderViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # SECURE: User can only see, edit, or delete their own orders
        # Even if an attacker requests /api/orders/999/, DRF returns 404 Not Found
        return Order.objects.filter(customer=self.request.user)

    def perform_create(self, serializer):
        # Automatically bind ownership on record creation
        serializer.save(customer=self.request.user)
```

---

## 4. Custom Object-Level Permissions in DRF

For granular access checks (e.g. only authors can edit, public can read):

```python
from rest_framework import permissions

class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Object-level permission to only allow owners of an object to edit it.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request (GET, HEAD, OPTIONS)
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions are only allowed to the owner of the snippet.
        return obj.owner == request.user
```

> [!WARNING]
> In DRF, `has_object_permission` is only called automatically when using `self.get_object()`. If you write custom actions (`@action`) and fetch objects manually via `Model.objects.get(...)`, DRF does **not** call `has_object_permission` unless you explicitly invoke `self.check_object_permissions(request, obj)`.

---

## 5. Sequential ID Enumeration vs UUIDs

While UUIDs do not replace authorization checks, using sequential auto-incrementing integer IDs (`/invoices/101/`, `/invoices/102/`) makes enumeration trivial for attackers.

```python
import uuid
from django.db import models

class SecureDocument(models.Model):
    # Use UUIDv4 or ULID for public-facing identifiers
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
```

---

## 6. Agent Review Checklist for IDOR
- [ ] Does every view accepting an entity identifier (`pk`, `id`, `uuid`) verify ownership or tenant isolation?
- [ ] Does the DRF ViewSet override `get_queryset()` to scope objects by `request.user`?
- [ ] Does `perform_create` explicitly bind ownership instead of trusting an `owner_id` passed in request payloads?
- [ ] Are custom DRF `@action` endpoints calling `self.check_object_permissions(request, obj)` or filtering queries safely?
