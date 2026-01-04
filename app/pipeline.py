from __future__ import annotations
import re
import time
from dataclasses import dataclass
from typing import List
from uuid import uuid4

from .moderation import (
    is_moderation_flagged,
    detect_sensitive_input,
    detect_injection,
    detect_secret_leak,
)
from .logging_utils import log_interaction
from .config import Config
from .web_search import answer_with_web_sources
from .kpi import emit_kpi_event
from .knowledge_base import KnowledgeBase, KnowledgeEntry
from .llm import summarize_context


@dataclass
class PipelineResponse:
    info: str
    answer: str
    sources: List[str]
    request_id: str
    moderation_flagged: bool
    sensitive_detected: bool


FALLBACK_TEXT = (
    "I do not have sufficient verified information to answer this question. "
    "Please consult your IT security team or official organisational guidance."
)

SENSITIVE_TEXT = (
    "I cannot process passwords, verification codes, or other sensitive data. "
    "Please contact your IT security team for support."
)

MODERATION_TEXT = (
    "I cannot assist with that request. Please consult your IT security team."
)

INSUFFICIENT_SEARCH_TEXT = (
    "Authoritative sources do not provide sufficient detail to answer this conclusively."
)

DEFAULT_SOURCE_URL = "https://www.cisa.gov/resources-tools/resources"


OUTPUT_LEAK_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----"),
    re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),  # JWT-ish
    re.compile(r"system prompt", re.IGNORECASE),
    re.compile(r"developer message", re.IGNORECASE),
]


def _output_leak_detected(text: str) -> bool:
    return any(p.search(text or "") for p in OUTPUT_LEAK_PATTERNS)


def _tokenize_query(text: str) -> set:
    return set(re.findall(r"[a-z0-9]+", (text or "").lower()))


def _format_slack(info: str, answer: str, sources: List[str]) -> str:
    cleaned_sources = []
    for src in sources or []:
        if src and src not in cleaned_sources:
            cleaned_sources.append(src)
    cleaned_sources = cleaned_sources[:3] or [DEFAULT_SOURCE_URL]
    lines = [info.strip(), "", answer.strip(), "", "Source:"]
    for src in cleaned_sources:
        lines.append(f"{src}")
    return "\n".join(lines)


class ResponsePipeline:
    def __init__(self):
        # Local KB fallback is disabled to favor live authoritative URLs.
        self.knowledge_base = None
        self.kb_threshold = Config.kb_confidence_threshold

    def generate(self, *, user_input: str, channel: str, session_id: str) -> PipelineResponse:
        request_id = str(uuid4())
        start_time = time.perf_counter()
        emit_kpi_event(
            event_type="qa_query_received",
            user_id=session_id,
            flags=[channel],
        )
        moderation_flagged = is_moderation_flagged(user_input)
        sensitive_detected = False

        if moderation_flagged:
            sources = [DEFAULT_SOURCE_URL]
            self._log(channel, request_id, session_id, True, False, sources)
            emit_kpi_event(
                event_type="qa_refused",
                user_id=session_id,
                flags=[channel, "moderation"],
            )
            return PipelineResponse(
                info="Moderation policy enforced.",
                answer=MODERATION_TEXT,
                sources=sources,
                request_id=request_id,
                moderation_flagged=True,
                sensitive_detected=False,
            )

        sensitive_detected = detect_sensitive_input(user_input)
        if sensitive_detected:
            sources = [DEFAULT_SOURCE_URL]
            self._log(channel, request_id, session_id, False, True, sources)
            emit_kpi_event(
                event_type="qa_refused",
                user_id=session_id,
                flags=[channel, "sensitive"],
            )
            return PipelineResponse(
                info="Sensitive data blocked.",
                answer=SENSITIVE_TEXT,
                sources=sources,
                request_id=request_id,
                moderation_flagged=False,
                sensitive_detected=True,
            )

        if detect_injection(user_input):
            safe_answer = "I cannot assist with that request. Please provide a cybersecurity awareness question."
            info_text = "Input blocked by safety filter."
            sources = [DEFAULT_SOURCE_URL]
            self._log(channel, request_id, session_id, False, False, sources)
            emit_kpi_event(
                event_type="qa_refused",
                user_id=session_id,
                flags=[channel, "injection"],
            )
            return PipelineResponse(
                info=info_text,
                answer=safe_answer,
                sources=sources,
                request_id=request_id,
                moderation_flagged=False,
                sensitive_detected=False,
            )

        web_answer, web_sources = answer_with_web_sources(user_input)
        answer_text = web_answer
        sources = web_sources[:3]
        info_text = "Live search across trusted cybersecurity authorities."
        web_used = bool(web_sources)

        if not answer_text:
            if sources:
                answer_text = "Refer to the cited sources for verified guidance."
                info_text = info_text or "Live search across trusted cybersecurity authorities."
            else:
                answer_text = INSUFFICIENT_SEARCH_TEXT if Config.enable_live_search else FALLBACK_TEXT
                info_text = info_text or "No authoritative sources matched the request."
        if not sources:
            sources = []

        inline_sources = sources[:3]
        final_answer = answer_text.strip() if answer_text else ""
        if not final_answer and sources:
            final_answer = "Refer to the cited sources for verified guidance."
        if _output_leak_detected(final_answer) or detect_secret_leak(final_answer):
            final_answer = "I cannot provide that information safely."
            sources = [DEFAULT_SOURCE_URL]

        self._log(channel, request_id, session_id, False, False, sources)
        latency_ms = int((time.perf_counter() - start_time) * 1000)
        if web_used:
            emit_kpi_event(
                event_type="web_search_used",
                user_id=session_id,
                latency_ms=latency_ms,
                flags=[channel],
            )
        emit_kpi_event(
            event_type="qa_answered",
            user_id=session_id,
            latency_ms=latency_ms,
            flags=[channel],
        )
        return PipelineResponse(
            info=info_text,
            answer=final_answer,
            sources=sources,
            request_id=request_id,
            moderation_flagged=False,
            sensitive_detected=False,
        )

    def _compose_kb(self, question: str, entries: List[KnowledgeEntry]) -> tuple[str, List[str]]:
        MAX_CONTEXT_CHARS = 6000
        context_chunks: List[str] = []
        current_size = 0
        query_tokens = _tokenize_query(question)
        for entry in entries[:4]:
            payload = (entry.content or "").strip()
            if not payload:
                continue
            if payload.lower().startswith("disclaimer"):
                continue
            sentences = re.split(r"(?<=[.!?])\s+", payload)
            relevant_sentences = [
                sent.strip()
                for sent in sentences
                if sent.strip()
                and (not query_tokens or any(token in sent.lower() for token in query_tokens))
            ]
            selected = relevant_sentences or [sent.strip() for sent in sentences if sent.strip()]
            if not selected:
                continue
            snippet = " ".join(selected[:8])[:1500]
            title = entry.title.strip() or "Untitled"
            tag = f"Title: {title}\nSource: {entry.source}"
            block = f"{tag}\n{snippet}"
            block_len = len(block)
            if current_size + block_len > MAX_CONTEXT_CHARS:
                remaining = MAX_CONTEXT_CHARS - current_size
                if remaining <= 0:
                    break
                block = block[:remaining]
                block_len = len(block)
            context_chunks.append(block)
            current_size += block_len
            if current_size >= MAX_CONTEXT_CHARS:
                break

        base_context = "\n\n".join(context_chunks).strip()
        enriched_context = f"Question: {question.strip()}\n\n{base_context}" if question else base_context
        summary = summarize_context(question, enriched_context) if base_context else ""
        if not summary:
            fallback_entry = entries[0].content.strip() if entries else ""
            summary = fallback_entry or FALLBACK_TEXT

        sources: List[str] = []
        seen = set()
        for entry in entries:
            src = entry.source.strip()
            if not src:
                continue
            if src not in seen:
                sources.append(src)
                seen.add(src)
            if len(sources) >= 4:
                break
        if not sources:
            sources = [DEFAULT_SOURCE_URL]

        return summary.strip(), sources

    def _log(
        self,
        channel: str,
        request_id: str,
        session_id: str,
        moderation: bool,
        sensitive: bool,
        sources: List[str],
        ):
        valid_sources = [s for s in sources if s != "N/A"]
        log_interaction(
            channel=channel,
            request_id=request_id,
            session_id=session_id,
            moderation_flagged=moderation,
            sensitive_input_detected=sensitive,
            number_of_sources_used=len(valid_sources),
            source_list=valid_sources,
        )

    def _answer_from_kb(self, question: str) -> tuple[str, List[str]]:
        return "", []


def slack_response_formatter(info: str, answer: str, sources: List[str]) -> str:
    info_text = (info or "Trusted cybersecurity knowledge sources.").strip()
    answer_text = (answer or FALLBACK_TEXT).strip()
    cleaned_sources: List[str] = []
    for src in sources or []:
        clean = src.strip()
        if not clean:
            continue
        if clean not in cleaned_sources:
            cleaned_sources.append(clean)
    if not cleaned_sources:
        cleaned_sources = [DEFAULT_SOURCE_URL]
    lines = [info_text, "", answer_text, "", "Source:"]
    for src in cleaned_sources:
        lines.append(f"{src}")
    return "\n".join(lines)
