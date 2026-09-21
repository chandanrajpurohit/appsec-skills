# File Upload Security in Django

Allowing users to upload files introduces major security risks if unvetted:
- **Remote Code Execution (RCE)**: Uploading web-executable scripts (`.py`, `.php`, `.cgi`, `.html`) that the web server executes.
- **Cross-Site Scripting (XSS)**: Uploading malicious SVGs containing `<script>` tags or HTML files served directly from the same origin.
- **Path Traversal**: Manipulating filenames (e.g., `../../etc/cron.d/malicious`) to overwrite system files.
- **Denial of Service (Zip Bombs / Decompression Bombs)**: Uploading small archives that expand to hundreds of gigabytes.

---

## 1. Secure Model Configuration

### Unpredictable Filename Generation (UUIDs)
Never store files on disk using the raw client-supplied filename (`file.name`). Instead, generate a unique filename with a validated extension:

```python
import os
import uuid
from django.db import models

def secure_upload_path(instance, filename):
    # Extract extension and convert to lowercase
    ext = os.path.splitext(filename)[1].lower()
    # Generate unique UUIDv4 filename
    unique_filename = f"{uuid.uuid4().hex}{ext}"
    # Return structured storage path (e.g., uploads/avatars/2026/09/a1b2c3...png)
    return os.path.join("uploads", "avatars", unique_filename)

class UserProfile(models.Model):
    avatar = models.FileField(upload_to=secure_upload_path)
```

---

## 2. File Validation: Extension & MIME Type Verification

Relying solely on `file.content_type` is insecure because the client controls the HTTP `Content-Type` header. Validate both the extension AND inspect the file's magic bytes.

### Custom File Validator
```python
import os
from django.core.exceptions import ValidationError
from django.utils.deconstruct import deconstructible

@deconstructible
class SecureFileValidator:
    def __init__(self, allowed_extensions, max_size_mb=5):
        self.allowed_extensions = [ext.lower() for ext in allowed_extensions]
        self.max_size_bytes = max_size_mb * 1024 * 1024

    def __call__(self, file):
        # 1. Validate size
        if file.size > self.max_size_bytes:
            raise ValidationError(f"File size exceeds the {self.max_size_bytes // (1024*1024)}MB limit.")

        # 2. Validate extension
        ext = os.path.splitext(file.name)[1].lower().lstrip(".")
        if ext not in self.allowed_extensions:
            raise ValidationError(f"Unsupported file extension '.{ext}'. Allowed: {', '.join(self.allowed_extensions)}")

        # 3. Validate Magic Bytes (using python-magic / pure-python inspection)
        file.seek(0)
        header = file.read(2048)
        file.seek(0)  # Reset pointer for subsequent storage operations

        # Example magic byte signatures
        signatures = {
            "png": b"\x89PNG\r\n\x1a\n",
            "jpg": b"\xff\xd8\xff",
            "jpeg": b"\xff\xd8\xff",
            "pdf": b"%PDF",
        }

        expected_sig = signatures.get(ext)
        if expected_sig and not header.startswith(expected_sig):
            raise ValidationError("File content signature does not match the file extension.")
```

### Usage in Django Models:
```python
validate_image = SecureFileValidator(allowed_extensions=["png", "jpg", "jpeg"], max_size_mb=2)

class Document(models.Model):
    file = models.FileField(upload_to=secure_upload_path, validators=[validate_image])
```

---

## 3. The SVG Danger (Stored XSS)
Scalable Vector Graphics (`.svg`) files are XML documents that can execute embedded JavaScript:

```xml
<!-- DANGEROUS SVG PAYLOAD -->
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.cookie);</script>
</svg>
```

**Mitigations**:
1. Do not allow users to upload SVGs unless strictly necessary.
2. If SVGs must be supported, sanitize them server-side using `defusedxml` and an SVG sanitizer (e.g. `scour` or `svgcheck`), OR serve SVGs from an isolated sandbox domain with `Content-Disposition: attachment` and `Content-Security-Policy: sandbox`.

---

## 4. Serving Uploaded Files Safely
- **Never serve user uploads from the same origin that handles sensitive session cookies.**
  - Use isolated storage buckets (AWS S3, Google Cloud Storage, Cloudflare R2) with a dedicated domain (e.g., `cdn-usercontent.example.com`).
- Always serve user-uploaded downloads with proper headers:
  ```http
  Content-Disposition: attachment; filename="safe_name.pdf"
  X-Content-Type-Options: nosniff
  ```
- Restrict web server execution permissions on the media directory (e.g., in Nginx, disable PHP/Python execution in `/media/`).

---

## 5. Agent Review Checklist for File Uploads
- [ ] Are uploaded files stored with unpredictable filenames (UUIDs) rather than raw user filenames?
- [ ] Is file size strictly validated before processing?
- [ ] Are file extensions restricted to a safe, minimal allowlist?
- [ ] Are magic bytes inspected to ensure content matches extension?
- [ ] Are uploaded SVGs either rejected, sanitized, or served as downloads (`Content-Disposition: attachment`)?
- [ ] Is user media isolated from the main domain via cloud storage or a separate origin?
