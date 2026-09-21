---
name: django
description: Application security guide, audit checklist, and static scanner for Django and DRF web applications. Use when writing, refactoring, or reviewing Django views, ORM queries, models, serializers, forms, authentication flows, file uploads, or production settings.
license: Complete terms in LICENSE.txt
---

# Django Application Security

This skill guides AI agents in identifying, preventing, and remediating application security vulnerabilities across Django applications and Django REST Framework (DRF) APIs.

**Helper Scripts Available**:
- `scripts/audit.py` - AST and pattern static security scanner for Django projects

**Always run scripts with `--help` first** to see usage. DO NOT read the source until you try running the script first and find that a customized solution is absolutely necessary. These scripts can be very large and thus pollute your context window. They exist to be called directly as black-box scripts rather than ingested into your context window.

---

## Decision Tree: Choosing Your Approach

```
Django Task → What area of the application are you working on?
    ├─ Views / APIs → Is authentication and object-level ownership verified?
    │       ├─ No → Filter database query by request.user / organization
    │       └─ Yes → Check CSRF token & rate limiting
    │
    ├─ Database / ORM → Are raw queries or cursors used?
    │       ├─ Yes → Parameterize with placeholders (%s); eliminate f-strings
    │       └─ No → Use standard ORM filter/exclude
    │
    ├─ Serializers (DRF) → Is fields = '__all__' present?
    │       ├─ Yes → Replace with explicit list; mark sensitive fields write_only=True
    │       └─ No → Proceed with scoped validation
    │
    ├─ File Uploads → Are uploaded filenames preserved from client?
    │       ├─ Yes → Generate UUID filenames, validate magic bytes & size
    │       └─ No → Verify storage isolation
    │
    └─ Deployment / Settings → Is DEBUG = True or ALLOWED_HOSTS = ['*']?
            ├─ Yes → Bind to environment variables; enforce HSTS & secure cookies
            └─ No → Run: python manage.py check --deploy
```

---

## Quick Reference Workflow

### 1. Run Automated Security Scanner
Run the included AST security scanner on your target directory:
```bash
python scripts/audit.py /path/to/django/project
```

### 2. View & API Authorization (IDOR Defense)
Never retrieve objects using an unvalidated primary key without verifying requesting user ownership:
```python
# VULNERABLE: Direct access without ownership check
doc = Document.objects.get(id=doc_id)

# SECURE: Scoped to authenticated user
doc = get_object_or_404(Document, id=doc_id, owner=request.user)
```
See: [authz-idor.md](./references/authz-idor.md)

### 3. ORM & SQL Injection Defense
Never use string formatting (f-strings, `.format()`, `%`) in raw SQL:
```python
# VULNERABLE: f-string interpolation
User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{username}'")

# SECURE: Parameterized placeholder
User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [username])
```
See: [orm-sql-injection.md](./references/orm-sql-injection.md)

### 4. XSS & Template Escaping (`mark_safe`)
Avoid using `mark_safe` on raw user inputs. If rich HTML is required, sanitize with `nh3`:
```python
import nh3
from django.utils.safestring import mark_safe

clean_html = nh3.clean(user_input, tags={"p", "b", "i", "strong", "em", "a"})
safe_content = mark_safe(clean_html)
```
See: [xss-csrf-defense.md](./references/xss-csrf-defense.md)

### 5. Production Settings Checklist
- `DEBUG = False`
- `SECRET_KEY` loaded from environment
- `ALLOWED_HOSTS` explicit (no wildcard `*`)
- `SESSION_COOKIE_SECURE = True`
- `CSRF_COOKIE_SECURE = True`
- `SECURE_SSL_REDIRECT = True`
- `SECURE_HSTS_SECONDS = 31536000`
See: [settings-hardening.md](./references/settings-hardening.md) and [secure_settings.py](./examples/secure_settings.py)

---

## References Directory

- [Production Settings Hardening](./references/settings-hardening.md)
- [Preventing SQL Injection in Django ORM](./references/orm-sql-injection.md)
- [Authorization & IDOR / BOLA Prevention](./references/authz-idor.md)
- [XSS & CSRF Defense](./references/xss-csrf-defense.md)
- [Secure File Upload Handling](./references/file-upload-security.md)
- [Django REST Framework API Security](./references/api-drf-security.md)
- [Vulnerable vs Secure Code Examples](./examples/vulnerable_vs_secure.py)
- [Production-Ready Hardened Settings](./examples/secure_settings.py)
