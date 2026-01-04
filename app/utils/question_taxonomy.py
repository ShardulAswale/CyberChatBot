from __future__ import annotations

from typing import Dict, List, Tuple

MODULE_KEYWORDS: Dict[str, List[str]] = {
    "phishing": [
        "phishing",
        "smishing",
        "vishing",
        "email",
        "link",
        "inbox",
        "sms",
        "call",
        "spoof",
    ],
    "identity": [
        "password",
        "credential",
        "login",
        "mfa",
        "two-factor",
        "authentication",
        "manager",
    ],
    "malware": [
        "malware",
        "virus",
        "worm",
        "spyware",
        "ransomware",
        "trojan",
        "payload",
        "infection",
    ],
    "devices": [
        "device",
        "wifi",
        "vpn",
        "patch",
        "update",
        "usb",
        "mobile",
        "laptop",
    ],
    "policies": [
        "policy",
        "compliance",
        "gdpr",
        "hipaa",
        "iso",
        "standard",
        "framework",
        "training",
    ],
}

MODULE_DETAILS = {
    "phishing": {
        "topic": "Phishing and social engineering",
        "relevant_info": "Verify unexpected messages and report suspicious links before clicking.",
        "keywords": ["phishing", "spoofing", "social engineering"],
        "data": {
            "primary_risk": "Credential theft",
            "recommended_actions": [
                "Report suspicious messages",
                "Hover over links",
                "Use official channels",
            ],
        },
        "skill_focus": "Evaluate and report suspicious communication",
    },
    "identity": {
        "topic": "Identity and access controls",
        "relevant_info": "Use long, unique passwords and enable MFA wherever possible.",
        "keywords": ["password", "mfa", "credential hygiene"],
        "data": {
            "primary_risk": "Account takeover",
            "recommended_actions": [
                "Adopt password managers",
                "Rotate credentials securely",
                "Enable MFA",
            ],
        },
        "skill_focus": "Strengthen authentication posture",
    },
    "malware": {
        "topic": "Malware and endpoint threats",
        "relevant_info": "Maintain up-to-date defenses and avoid unknown downloads.",
        "keywords": ["malware", "ransomware", "spyware"],
        "data": {
            "primary_risk": "System compromise",
            "recommended_actions": [
                "Patch regularly",
                "Use vetted software",
                "Run antivirus scans",
            ],
        },
        "skill_focus": "Identify malware behavior and prevention",
    },
    "devices": {
        "topic": "Secure devices and networks",
        "relevant_info": "Keep devices patched, encrypt data, and prefer secure networks.",
        "keywords": ["vpn", "wifi", "device hardening"],
        "data": {
            "primary_risk": "Data interception or loss",
            "recommended_actions": [
                "Use VPN on public Wi-Fi",
                "Apply OS and firmware updates",
                "Restrict removable media",
            ],
        },
        "skill_focus": "Device hardening and safe connectivity",
    },
    "policies": {
        "topic": "Policies, compliance, and governance",
        "relevant_info": "Align daily practices with required frameworks and reporting expectations.",
        "keywords": ["policy", "compliance", "audit"],
        "data": {
            "primary_risk": "Regulatory fines or data exposure",
            "recommended_actions": [
                "Follow policy guidance",
                "Document adherence",
                "Complete training on time",
            ],
        },
        "skill_focus": "Governance awareness and reporting",
    },
    "general": {
        "topic": "Cybersecurity essentials",
        "relevant_info": "Understand the fundamentals that support secure behavior everywhere.",
        "keywords": ["awareness", "basics", "cyber hygiene"],
        "data": {
            "primary_risk": "General exposure",
            "recommended_actions": [
                "Stay informed",
                "Share suspicious activity with IT",
                "Adopt safe defaults",
            ],
        },
        "skill_focus": "General awareness",
    },
}

LEVEL_LABEL = {1: "Foundational", 2: "Intermediate", 3: "Advanced"}


def classify_module(question: str, answer: str) -> str:
    blob = f"{question} {answer}".lower()
    for module, keywords in MODULE_KEYWORDS.items():
        if any(keyword in blob for keyword in keywords):
            return module
    return "general"


def module_metadata(
    question_text: str, answer_text: str, level: int
) -> Tuple[str, str, Dict[str, object], Dict[str, object]]:
    module = classify_module(question_text, answer_text)
    module_details = MODULE_DETAILS.get(module, MODULE_DETAILS["general"])
    attributes = {
        "topic": module_details["topic"],
        "keywords": module_details["keywords"],
        "level_label": LEVEL_LABEL.get(level, "Foundational"),
        "skill_focus": module_details["skill_focus"],
        "difficulty": LEVEL_LABEL.get(level, "Foundational").lower(),
    }
    data = module_details["data"]
    relevant_info = module_details["relevant_info"]
    return module, relevant_info, attributes, data
