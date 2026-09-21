# Cross-Site Scripting (XSS) & CSRF Defense in Django

Django provides robust security primitives out of the box (automatic template escaping and `CsrfViewMiddleware`). Vulnerabilities are almost always introduced when developers deliberately bypass these protections or misconfigure API authentication.

---

## 1. Cross-Site Scripting (XSS)

### Django's Built-in Escaping
By default, the Django template engine HTML-escapes variables (`<` becomes `&lt;`, `>` becomes `&gt;`, `&` becomes `&amp;`, `"` becomes `&quot;`, `'` becomes `&#x27;`).

### The Danger of `mark_safe` and `|safe`
Developers often use `mark_safe` or the `|safe` filter to render HTML without realizing it renders user-supplied script tags:

#### Vulnerable Pattern
```python
from django.utils.safestring import mark_safe
from django.shortcuts import render

def user_bio_vulnerable(request):
    bio_html = request.POST.get("bio", "")
    # CRITICAL: If bio_html contains <script>alert(1)</script> or <img src=x onerror=...>,
    # mark_safe disables Django's escaping and renders the exploit directly!
    context = {"bio": mark_safe(bio_html)}
    return render(request, "bio.html", context)
```

#### Secure Pattern: Sanitize Before Rendering
If the application must support formatted rich text (e.g. from Markdown or WYSIWYG editors), sanitize it using `nh3` (Python binding to Mozilla's Ammonia) or `bleach`:

```python
import nh3
from django.utils.safestring import mark_safe

ALLOWED_TAGS = {"p", "b", "i", "strong", "em", "a", "ul", "ol", "li", "code", "pre"}
ALLOWED_ATTRIBUTES = {"a": {"href", "title"}}

def clean_html(user_input: str) -> str:
    cleaned = nh3.clean(
        user_input,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        url_schemes={"http", "https", "mailto"},
    )
    return mark_safe(cleaned)
```

### JSON Script Tag Escaping in Templates
When embedding Python/Django dictionaries into `<script>` tags:

```html
<!-- VULNERABLE: Direct variable in script tag is vulnerable to closing script tag injection -->
<script>
    const userData = {{ user_data|safe }};
</script>

<!-- SECURE: Use Django's json_script template filter -->
{{ user_data|json_script:"user-data-json" }}
<script>
    const userData = JSON.parse(document.getElementById('user-data-json').textContent);
</script>
```

---

## 2. Cross-Site Request Forgery (CSRF)

### How Django Protects Against CSRF
Django's `django.middleware.csrf.CsrfViewMiddleware` generates a secret token per session/cookie and verifies that unsafe HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`) contain a matching token in the request header or POST form body.

### Safe Template Forms
Always include `{% csrf_token %}` inside any `<form method="post">`:
```html
<form method="post" action="/profile/update/">
    {% csrf_token %}
    {{ form.as_p }}
    <button type="submit">Save Changes</button>
</form>
```

### The Pitfall of `@csrf_exempt`
Using `@csrf_exempt` completely disables CSRF protection on a view:

```python
from django.views.decorators.csrf import csrf_exempt

# HIGH RISK: An attacker can host malicious site with auto-submitting form targeting this URL
@csrf_exempt
def transfer_funds_vulnerable(request):
    if request.method == "POST":
        # Attacker forces user's browser to send authenticated request with cookies!
        recipient = request.POST.get("recipient")
        amount = request.POST.get("amount")
        # Transfers funds...
```

#### When is `@csrf_exempt` Acceptable?
Only when the endpoint uses non-cookie based authentication (e.g., Bearer tokens, API keys in headers, or HMAC webhook signatures):

```python
import hmac, hashlib
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseForbidden

@csrf_exempt
def webhook_receiver(request):
    signature = request.headers.get("X-Hub-Signature-256")
    expected_sig = "sha256=" + hmac.new(WEBHOOK_SECRET, request.body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_sig):
        return HttpResponseForbidden("Invalid webhook signature")
    # Process webhook safely
```

### Single-Page Applications (SPAs) & DRF CSRF Handling
When using Django Session Authentication with a frontend like Next.js or React:
1. Ensure `CSRF_COOKIE_HTTPONLY = False` if the frontend needs to read the cookie via JavaScript to send the `X-CSRFToken` header.
2. In `settings.py`, configure trusted origins:
   ```python
   CSRF_TRUSTED_ORIGINS = [
       "https://app.example.com",
       "https://admin.example.com",
   ]
   ```
3. Pass `X-CSRFToken` in your frontend request headers.

---

## 3. Agent Review Checklist for XSS & CSRF
- [ ] Are any occurrences of `mark_safe` or `|safe` rendering unescaped user input?
- [ ] Are user-supplied rich text fields sanitized with a strict allowlist (e.g. `nh3` or `bleach`) before being marked safe?
- [ ] Are JSON payloads embedded in templates using `{{ data|json_script:"elem-id" }}` rather than raw `<script>` tags?
- [ ] Are any state-changing endpoints marked with `@csrf_exempt` while still accepting session/cookie credentials?
- [ ] Is `CSRF_TRUSTED_ORIGINS` configured strictly without wildcards (`*`)?
