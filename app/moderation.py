import re


MODERATION_KEYWORDS = {
    "ddos",
    "exploit",
    "malicious payload",
    "bypass security",
    "disable firewall",
}

SENSITIVE_PATTERNS = [
    re.compile(r"(password|passcode|otp|one[- ]time code|pin code)", re.IGNORECASE),
    re.compile(r"(api[-_\s]?key|secret key|access key|token)", re.IGNORECASE),
    re.compile(r"(AKIA[0-9A-Z]{16})"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
]

INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"system prompt",
    r"developer message",
    r"reveal hidden",
    r"jailbreak",
    r"\bDAN\b",
    r"\bact as\b",
    r"\byou are chatgpt\b",
    r"tool instructions",
    r"print secrets",
    r"bypass policy",
    r"exfiltrate",
    r"begin system prompt",
    r"end system prompt",
]
INJECTION_REGEX = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)

SECRET_LEAK_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----"),
    re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
    re.compile(r"AWS_ACCESS_KEY_ID", re.IGNORECASE),
    re.compile(r"AWS_SECRET_ACCESS_KEY", re.IGNORECASE),
    re.compile(r"OPENAI_API_KEY", re.IGNORECASE),
    re.compile(r"GOOGLE_API_KEY", re.IGNORECASE),
    re.compile(r"(otp|one[-\s]?time|pin code)", re.IGNORECASE),
]


def is_moderation_flagged(text: str) -> bool:
    lowered = (text or "").lower()
    return any(keyword in lowered for keyword in MODERATION_KEYWORDS)


def detect_sensitive_input(text: str) -> bool:
    candidate = text or ""
    return any(pattern.search(candidate) for pattern in SENSITIVE_PATTERNS)


def detect_injection(text: str) -> bool:
    return bool(INJECTION_REGEX.search(text or ""))


def detect_secret_leak(text: str) -> bool:
    return any(p.search(text or "") for p in SECRET_LEAK_PATTERNS)
