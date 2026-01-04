import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List
from urllib.parse import urlparse

from .config import Config


@dataclass
class KnowledgeEntry:
    id: str
    title: str
    content: str
    bullets: List[str]
    source: str
    keywords: set
    trusted: bool
    domain: str


class KnowledgeBase:
    def __init__(self):
        self.trusted_domains: List[str] = Config.allowed_domains
        self.entries: List[KnowledgeEntry] = self._load_entries()

    def _load_entries(self) -> List[KnowledgeEntry]:
        entries: List[KnowledgeEntry] = []
        entries.extend(self._load_index_entries())
        if Config.include_internal_qa:
            entries.extend(self._load_internal_questions())
        return entries

    def _load_index_entries(self) -> List[KnowledgeEntry]:
        index_path = Path("index/index.json")
        if not index_path.exists():
            return []

        with open(index_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        if isinstance(raw_data, dict):
            documents = raw_data.get("documents", [])
            self.trusted_domains = raw_data.get("trusted_domains", self.trusted_domains)
        else:
            documents = raw_data

        entries: List[KnowledgeEntry] = []
        for item in documents:
            content = item.get("content", "")
            source = item.get("source", "")
            keywords = set(item.get("keywords", []))
            keywords.update(self._tokenize(item.get("title", "")))
            keywords.update(self._tokenize(content))
            domain = self._derive_domain(source)
            entries.append(
                KnowledgeEntry(
                    id=item.get("id", ""),
                    title=item.get("title", ""),
                    content=content,
                    bullets=item.get("bullets", []),
                    source=source,
                    keywords=keywords,
                    trusted=bool(item.get("trusted", False)),
                    domain=domain,
                )
            )
        return entries

    def _load_internal_questions(self) -> List[KnowledgeEntry]:
        qa_path = Path("MostAskedQ&A.json")
        if not qa_path.exists():
            return []

        with open(qa_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        entries: List[KnowledgeEntry] = []
        for row in data.get("questions", []):
            question = row.get("question_text", "")
            answer = row.get("answer_text", "")
            index_id = row.get("number", 0)
            keywords = self._tokenize(question) | self._tokenize(answer)
            entries.append(
                KnowledgeEntry(
                    id=f"mostasked_{index_id}",
                    title=question,
                    content=answer,
                    bullets=[],
                    source=f"MostAskedQ&A.json#Q{index_id}",
                    keywords=keywords,
                    trusted=True,
                    domain="internal",
                )
            )
        return entries

    def retrieve_scored(
        self, query: str, top_k: int = 3
    ) -> List[tuple[int, KnowledgeEntry]]:
        tokens = self._tokenize(query)
        if not tokens:
            return []

        scored = []
        for entry in self.entries:
            if not entry.trusted:
                continue
            score = self._score_entry(entry, tokens)
            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[:top_k]

    def retrieve(self, query: str, top_k: int = 3) -> List[KnowledgeEntry]:
        return [entry for _, entry in self.retrieve_scored(query, top_k=top_k)]

    def _score_entry(self, entry: KnowledgeEntry, tokens: set) -> int:
        score = 0
        for token in tokens:
            if token in entry.keywords:
                score += 3
            elif token in entry.content.lower():
                score += 1
        if score > 0 and entry.domain != "internal":
            score += 1
        return score

    @staticmethod
    def _tokenize(text: str) -> set:
        lowered = text.lower()
        tokens = re.findall(r"[a-z0-9]+", lowered)
        return set(tokens)

    @staticmethod
    def _derive_domain(source: str) -> str:
        if source.startswith("http"):
            parsed = urlparse(source)
            return parsed.netloc or "external"
        if source == "N/A":
            return "N/A"
        return "internal"
