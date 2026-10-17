import re
from typing import Any

CREDENTIAL_PATTERNS = [
    re.compile(r"(?i)(aws_secret_access_key|secret_key|secret|password|token)\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{16,})['\"]?"),
    re.compile(r"(?i)bearer\s+([a-zA-Z0-9\._\-]+)"),
]


def sanitize_dict(data: Any) -> Any:
    """Recursively traverses a dictionary or list, stripping sensitive credential patterns."""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            key_lower = str(k).lower()
            if any(s in key_lower for s in ["secret", "token", "password", "key_material", "credential"]):
                if (
                    "policy" in key_lower
                    or "passwordlength" in key_lower
                    or "passwordage" in key_lower
                    or "passwordreuse" in key_lower
                    or key_lower in [
                        "allowuserstochangepassword",
                        "expirepasswords",
                        "maxpasswordage",
                        "passwordreuseprevention",
                        "minimumpasswordlength",
                    ]
                ):
                    sanitized[k] = sanitize_dict(v)
                else:
                    sanitized[k] = "[REDACTED_BY_VYRA_GUARD]"
            else:
                sanitized[k] = sanitize_dict(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_dict(item) for item in data]
    elif isinstance(data, str):
        val = data
        for pattern in CREDENTIAL_PATTERNS:
            if pattern.groups >= 1:
                val = pattern.sub(r"\1: [REDACTED]", val)
            else:
                val = pattern.sub("[REDACTED]", val)
        return val
    return data
