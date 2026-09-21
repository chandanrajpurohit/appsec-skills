# Preventing SQL Injection in Django

Django's Object-Relational Mapper (ORM) constructs parameterized queries automatically when using standard query methods (`filter()`, `exclude()`, `annotate()`). However, developers and AI agents frequently introduce SQL Injection (SQLi) when dropping into raw SQL interfaces or dynamic query construction.

---

## 1. Safe vs Vulnerable ORM Querying

### Vulnerable: String Formatting in `raw()`
```python
# CRITICAL VULNERABILITY: User input directly concatenated into SQL query string
def search_users_vulnerable(request):
    username = request.GET.get("username", "")
    query = f"SELECT * FROM auth_user WHERE username = '{username}'"
    return User.objects.raw(query)
```
*Attack payload*: `' OR '1'='1` returns every user; `'; DROP TABLE auth_user; --` deletes the table.

### Secure: Parameterized `raw()`
```python
# SECURE: Parameters passed as a list/tuple to the database driver for escaping
def search_users_secure(request):
    username = request.GET.get("username", "")
    query = "SELECT * FROM auth_user WHERE username = %s"
    return User.objects.raw(query, [username])
```

---

## 2. Low-Level Database Cursors (`connection.cursor()`)

When bypassing the ORM completely:

### Vulnerable: String Interpolation
```python
from django.db import connection

def get_orders_vulnerable(status):
    with connection.cursor() as cursor:
        # DANGEROUS: f-string or .format()
        cursor.execute(f"SELECT id, total FROM orders WHERE status = '{status}'")
        return cursor.fetchall()
```

### Secure: Parameterized Cursor Execution
```python
from django.db import connection

def get_orders_secure(status):
    with connection.cursor() as cursor:
        # SECURE: Use %s placeholder regardless of database engine (PostgreSQL, SQLite, MySQL)
        cursor.execute("SELECT id, total FROM orders WHERE status = %s", [status])
        return cursor.fetchall()
```
> [!IMPORTANT]
> Always use `%s` placeholders for parameterized queries in Django cursors, even on SQLite or PostgreSQL. Do **not** wrap `%s` in quotes (e.g. `'%s'`), as this converts the placeholder into a literal string.

---

## 3. Dangerous ORM Methods: `extra()` and `RawSQL`

### `QuerySet.extra()`
`extra()` is considered an obsolete and dangerous API in Django:
```python
# VULNERABLE: Direct string interpolation into where clause
Entry.objects.extra(where=[f"headline = '{user_input}'"])

# SECURE: Use params list
Entry.objects.extra(where=["headline = %s"], params=[user_input])

# BEST PRACTICE: Avoid extra() completely; use standard ORM filter:
Entry.objects.filter(headline=user_input)
```

### `RawSQL` Annotations
When using `django.db.models.expressions.RawSQL`:
```python
from django.db.models.expressions import RawSQL

# VULNERABLE:
Book.objects.annotate(val=RawSQL(f"calc_score('{category}')", []))

# SECURE: Pass dynamic parameters in params argument
Book.objects.annotate(val=RawSQL("calc_score(%s)", [category]))
```

---

## 4. SQLi via Column / Table Name Injection

Parameterized queries escape **values**, not identifier names (table names, column names, ordering fields).

```python
# VULNERABLE: User controls order_by field directly
sort_field = request.GET.get("sort", "created_at")
# If sort_field is manipulated or combined with raw sql expressions:
users = User.objects.order_by(sort_field)
```

### Secure Whitelisting Pattern:
```python
ALLOWED_SORT_FIELDS = {
    "name": "username",
    "date": "created_at",
    "email": "email",
}

sort_key = request.GET.get("sort", "date")
order_field = ALLOWED_SORT_FIELDS.get(sort_key, "created_at")

# Safely apply direction if requested
direction = "-" if request.GET.get("order") == "desc" else ""
users = User.objects.order_by(f"{direction}{order_field}")
```

---

## 5. Agent Review Checklist for SQLi
- [ ] Are any f-strings, `.format()`, or `%` operators used to construct queries passed to `.raw()`, `.extra()`, or `cursor.execute()`?
- [ ] Are parameter values passed as a secondary sequence (list/tuple) argument?
- [ ] Are dynamic column names or table names validated against a strict static dictionary/whitelist?
- [ ] Is raw SQL avoided when standard Django ORM expressions (`F()`, `Q()`, `Subquery`, `Exists`) can achieve the same result?
