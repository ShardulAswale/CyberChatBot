import json
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

logger = logging.getLogger("cybersec_bot")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


def _domain_from_source(source: str) -> str:
    if source.startswith("http"):
        parsed = urlparse(source)
        return parsed.netloc or "external"
    if source == "N/A":
        return "N/A"
    return f"internal:{source}"


def log_interaction(
    *,
    channel: str,
    request_id: str,
    session_id: str,
    moderation_flagged: bool,
    sensitive_input_detected: bool,
    number_of_sources_used: int,
    source_list: list[str],
):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "session_id": session_id,
        "channel": channel,
        "moderation_flagged": moderation_flagged,
        "sensitive_input_detected": sensitive_input_detected,
        "number_of_sources_used": number_of_sources_used,
        "source_domains_used": [_domain_from_source(src) for src in source_list],
    }
    logger.info(json.dumps(event))


def log_event(event_type: str, data: dict):
    payload = {"event": event_type, **data}
    logger.info(json.dumps(payload))
