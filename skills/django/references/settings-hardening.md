# Django Production Settings Hardening Reference

This guide outlines security configurations for Django `settings.py`. Misconfigured settings represent one of the most common AppSec findings in production Django deployments.

---

## 1. Core Production Toggles

### `DEBUG`
- **Rule**: `DEBUG` must ALWAYS evaluate to `False` in production.
- **Risk**: When `DEBUG = True`, unhandled exceptions display tracebacks exposing environment variables, database credentials, internal server paths, and application secrets.
- **Secure Pattern**:
  ```python
  import os

  DEBUG = os.environ.get("DJANGO_DEBUG", "False").lower() in ("true", "1", "t")
  ```

### `SECRET_KEY`
- **Rule**: Never commit `SECRET_KEY` to version control. Must have high entropy (at least 50 random characters).
- **Risk**: Compromised `SECRET_KEY` allows attackers to forge session cookies, sign arbitrary cryptographic tokens, bypass CSRF checks, and execute remote code in certain deserialization scenarios.
- **Secure Pattern**:
  ```python
  from django.core.exceptions import ImproperlyConfigured

  SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY")
  if not SECRET_KEY and not DEBUG:
      raise ImproperlyConfigured("DJANGO_SECRET_KEY environment variable is missing!")
  ```

### `ALLOWED_HOSTS`
- **Rule**: Never set `ALLOWED_HOSTS = ['*']` in production.
- **Risk**: Setting wildcard `*` allows HTTP Host Header attacks, leading to cache poisoning, password reset link hijacking, and SSRF bypasses.
- **Secure Pattern**:
  ```python
  ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "").split(",")
  # Example: DJANGO_ALLOWED_HOSTS="app.example.com,api.example.com"
  ```

---

## 2. Cookie Security Flags

Session and CSRF cookies must be protected against theft via JavaScript (XSS) and transmission over unencrypted connections.

| Setting | Recommended Value | Security Benefit |
| :--- | :--- | :--- |
| `SESSION_COOKIE_SECURE` | `True` | Transmits session cookie only over HTTPS. |
| `CSRF_COOKIE_SECURE` | `True` | Transmits CSRF cookie only over HTTPS. |
| `SESSION_COOKIE_HTTPONLY` | `True` (Django default) | Prevents client-side JS (`document.cookie`) from reading the session. |
| `CSRF_COOKIE_HTTPONLY` | `True` (if not reading via JS) | Blocks JS access to CSRF cookie if token is rendered in forms/headers. |
| `SESSION_COOKIE_SAMESITE` | `'Lax'` or `'Strict'` | Protects against Cross-Site Request Forgery via third-party contexts. |
| `CSRF_COOKIE_SAMESITE` | `'Lax'` or `'Strict'` | Restricts cross-site CSRF token transmission. |
| `SESSION_EXPIRE_AT_BROWSER_CLOSE` | `True` (for sensitive apps) | Terminates sessions when the user closes their browser window. |

```python
# Production Cookie Hardening
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
```

---

## 3. HTTPS & SSL Redirection

Enforce TLS across all requests using Django's `SecurityMiddleware`:

```python
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    # ... other middlewares
]

# HTTPS Redirection
SECURE_SSL_REDIRECT = not DEBUG

# HTTP Strict Transport Security (HSTS)
# Informs browsers to only communicate via HTTPS for 1 year (31536000 seconds)
SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG

# Proxy header (when behind Nginx / Cloudflare / ALB)
# Only set this if your reverse proxy strictly sanitizes the header!
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
```

---

## 4. HTTP Security Headers

```python
# Prevent MIME-type sniffing (Content-Type header confusion attacks)
SECURE_CONTENT_TYPE_NOSNIFF = True

# Defend against Clickjacking
X_FRAME_OPTIONS = "DENY"  # or 'SAMEORIGIN' if frames are required within same origin

# Referrer Policy
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
```

### Content Security Policy (CSP)
Install `django-csp` (`pip install django-csp`) and configure:
```python
MIDDLEWARE = [
    # ...
    "csp.middleware.CSPMiddleware",
]

CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")  # Migrate to nonces where feasible
CSP_IMG_SRC = ("'self'", "data:", "https://cdn.example.com")
CSP_FRAME_ANCESTORS = ("'none'",)
```

---

## 5. Automated Verification
Always run Django's built-in deployment checker:
```bash
python manage.py check --deploy
```
This check flags missing cookie flags, disabled HSTS, and unsafe `DEBUG` states.
