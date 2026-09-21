# Django REST Framework (DRF) API Security

APIs built with Django REST Framework face distinct security challenges including mass assignment (over-posting), sensitive credential leakage, broken object level authorization, and unthrottled endpoints.

---

## 1. Mass Assignment (Over-Posting) via Serializers

When a serializer uses `fields = '__all__'`, any field present on the model can be updated by an attacker if submitted in the JSON payload, including fields like `is_staff`, `is_superuser`, `role`, `account_balance`, or `verified`.

### Vulnerable Serializer
```python
from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # CRITICAL FLAW: Attacker can send {"is_staff": true, "is_superuser": true}
        fields = '__all__'
```

### Secure Serializer: Explicit Field Allowlist
```python
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # SECURE: Only editable profile fields exposed
        fields = ["first_name", "last_name", "bio", "avatar"]
        read_only_fields = ["id", "email", "date_joined", "is_staff", "is_active"]
```

---

## 2. Preventing Password & Secret Exposure

When creating users or handling credentials, password fields must never be serialized in API responses:

```python
class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type": "password"}
    )

    class Meta:
        model = User
        fields = ["id", "username", "email", "password"]

    def create(self, validated_data):
        # Always use create_user() to ensure password is encrypted/hashed
        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data.get("email"),
            password=validated_data["password"],
        )
        return user
```

---

## 3. Rate Limiting & Throttling

APIs must enforce rate limits to defend against brute-force attacks, credential stuffing, and DoS.

### Configuration in `settings.py`
```python
REST_FRAMEWORK = {
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "100/day",
        "user": "1000/day",
        "login": "5/minute",     # Strict scope for authentication endpoints
    },
}
```

### Applying Scoped Throttles to Authentication Views
```python
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

class LoginAPIView(APIView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "login"

    def post(self, request):
        # Authenticate user...
        pass
```

---

## 4. Default Permission Policies

Set a secure default permission class globally in `settings.py` rather than relying on developers remembering to add `permission_classes = [IsAuthenticated]` to every individual view.

```python
REST_FRAMEWORK = {
    # Default: Require authentication for ALL endpoints
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ],
}
```
*When an endpoint must be public (e.g. signup, healthcheck), explicitly override it with `permission_classes = [AllowAny]`.*

---

## 5. Agent Review Checklist for DRF
- [ ] Are all serializers using explicit `fields = [...]` rather than `'__all__'`?
- [ ] Are sensitive fields (`password`, `api_token`, `totp_secret`) marked with `write_only=True`?
- [ ] Is `DEFAULT_PERMISSION_CLASSES` set to `IsAuthenticated` in settings?
- [ ] Are login, registration, and password reset endpoints protected by scoped rate throttles?
- [ ] Are user passwords created via `User.objects.create_user()` or `user.set_password()` rather than direct assignment?
