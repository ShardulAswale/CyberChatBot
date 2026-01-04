from __future__ import annotations

import functools
from typing import Dict, Tuple

import requests
from langdetect import DetectorFactory, LangDetectException, detect

from app.config import Config

DetectorFactory.seed = 0

TRANSLATION_MODELS: Dict[Tuple[str, str], str] = {
    ("es", "en"): "Helsinki-NLP/opus-mt-es-en",
    ("en", "es"): "Helsinki-NLP/opus-mt-en-es",
}


def detect_language(text: str | None) -> str | None:
    if not text or not text.strip():
        return None
    try:
        return detect(text)
    except LangDetectException:
        return None


def _hf_translate(text: str, model: str) -> str:
    if not Config.hf_token or not text.strip():
        return text
    url = f"https://api-inference.huggingface.co/models/{model}"
    headers = {"Authorization": f"Bearer {Config.hf_token}"}
    try:
        response = requests.post(url, json={"inputs": text}, headers=headers, timeout=20)
        if response.status_code != 200:
            return text
        payload = response.json()
        if isinstance(payload, list):
            candidate = payload[0]
            if isinstance(candidate, dict):
                return candidate.get("translation_text", text)
            if isinstance(candidate, str):
                return candidate
        if isinstance(payload, dict):
            return payload.get("translation_text", text)
        return text
    except Exception:
        return text


@functools.lru_cache(maxsize=512)
def translate_text(text: str, target_lang: str, source_lang: str | None = None) -> str:
    cleaned = (text or "").strip()
    if not cleaned:
        return text
    source = (source_lang or detect_language(cleaned) or "").lower()
    target = target_lang.lower()
    if not source or source == target:
        return text
    model = TRANSLATION_MODELS.get((source, target))
    if not model:
        return text
    return _hf_translate(cleaned, model)


def ensure_language(text: str, target_lang: str) -> str:
    if not text:
        return text
    target_lang = (target_lang or "en").lower()
    if target_lang == "en":
        return text
    return translate_text(text, target_lang=target_lang)
