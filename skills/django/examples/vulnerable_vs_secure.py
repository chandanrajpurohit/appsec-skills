"""
Django AppSec Examples: Vulnerable vs Secure Patterns
"""

# ==============================================================================
# 1. SQL INJECTION (Raw Queries & Cursors)
# ==============================================================================

# --- VULNERABLE ---
def search_invoices_vulnerable(request):
    user_status = request.GET.get("status", "pending")
    # CRITICAL: f-string string interpolation directly into SQL
    query = f"SELECT * FROM billing_invoice WHERE status = '{user_status}'"
    return Invoice.objects.raw(query)

# --- SECURE ---
def search_invoices_secure(request):
    user_status = request.GET.get("status", "pending")
    # SECURE: Parameter placeholder passed to database driver
    query = "SELECT * FROM billing_invoice WHERE status = %s"
    return Invoice.objects.raw(query, [user_status])


# ==============================================================================
# 2. INSECURE DIRECT OBJECT REFERENCE (IDOR / BOLA)
# ==============================================================================

# --- VULNERABLE ---
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404
from django.http import JsonResponse

@login_required
def get_user_document_vulnerable(request, doc_id):
    # FLAW: Any authenticated user can read document belonging to any other user
    doc = get_object_or_404(Document, id=doc_id)
    return JsonResponse({"id": doc.id, "title": doc.title, "content": doc.content})

# --- SECURE ---
@login_required
def get_user_document_secure(request, doc_id):
    # SECURE: Scoped to requesting user's records
    doc = get_object_or_404(Document, id=doc_id, owner=request.user)
    return JsonResponse({"id": doc.id, "title": doc.title, "content": doc.content})


# ==============================================================================
# 3. CROSS-SITE SCRIPTING (XSS & mark_safe)
# ==============================================================================

# --- VULNERABLE ---
from django.utils.safestring import mark_safe
from django.shortcuts import render

def render_comment_vulnerable(request):
    comment_html = request.POST.get("comment", "")
    # FLAW: Disables auto-escaping on raw client input
    return render(request, "comment.html", {"comment": mark_safe(comment_html)})

# --- SECURE ---
import nh3

ALLOWED_TAGS = {"p", "b", "i", "strong", "em", "code", "a"}
ALLOWED_ATTRS = {"a": {"href"}}

def render_comment_secure(request):
    comment_html = request.POST.get("comment", "")
    # SECURE: Strict HTML sanitization allowlist before mark_safe
    clean_html = nh3.clean(comment_html, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS)
    return render(request, "comment.html", {"comment": mark_safe(clean_html)})


# ==============================================================================
# 4. MASS ASSIGNMENT (DRF Serializers)
# ==============================================================================

from rest_framework import serializers
from django.contrib.auth import get_user_model
User = get_user_model()

# --- VULNERABLE ---
class VulnerableUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # FLAW: Allows malicious client to set is_staff, is_superuser, etc.
        fields = "__all__"

# --- SECURE ---
class SecureUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name"]
        read_only_fields = ["id", "username", "email"]
