# build_index.py

import os
import re
import json
from typing import List, Dict, Set
from urllib.parse import urlparse, urljoin, urldefrag

import requests
from bs4 import BeautifulSoup

from config import Config

# -------------------------
# CONFIGURATION
# -------------------------

INDEX_DIR = "index"
INDEX_FILE = os.path.join(INDEX_DIR, "index.json")

HF_API_TOKEN = Config.hf_token
EMBED_MODEL = Config.hf_embed_model

allowed_domains = Config.allowed_domains

# Cybersecurity seed URLs (must match allowed_domains or they’ll be skipped)
SEED_URLS = [
    "https://owasp.org/www-project-top-ten/",
    "https://owasp.org/www-project-api-security/",
    "https://www.cisa.gov/resources-tools/resources",
    "https://www.sans.org/blog/top-cybersecurity-best-practices/",
]

MAX_PAGES_TOTAL = 40
REQUEST_TIMEOUT = 15


# -------------------------
# TEXT HELPERS
# -------------------------

def clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def is_allowed_url(url: str) -> bool:
    """
    Only keep URLs whose domain is in allowed_domains.
    """
    try:
        netloc = urlparse(url).netloc.lower()
        return any(netloc.endswith(d.lower()) for d in allowed_domains)
    except Exception:
        return False


def normalize_url(base_url: str, href: str) -> str:
    """
    Convert relative -> absolute, drop #fragments, ignore mailto:/javascript:
    """
    if not href:
        return ""
    href = href.strip()
    if href.startswith("mailto:") or href.startswith("javascript:"):
        return ""
    abs_url = urljoin(base_url, href)
    abs_url, _ = urldefrag(abs_url)
    return abs_url


# -------------------------
# FETCH PAGE
# -------------------------

def fetch_page(url: str) -> Dict:
    print(f"🌐 Fetching: {url}")
    r = requests.get(url, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()

    soup = BeautifulSoup(r.text, "html.parser")
    title = soup.title.string.strip() if soup.title else url
    body = soup.body.get_text(separator=" ") if soup.body else ""

    return {
        "title": title,
        "url": url,
        "text": clean_text(body),
    }


# -------------------------
# BFS CRAWLER FROM SEEDS
# -------------------------

def crawl_from_seeds() -> List[Dict]:
    visited: Set[str] = set()
    queue: List[str] = []
    pages: List[Dict] = []

    # Only use seeds that are in allowed_domains
    print("🚦 Checking seed URLs against allowed_domains...")
    for seed in SEED_URLS:
        if is_allowed_url(seed):
            print(f"✅ Using seed: {seed}")
            queue.append(seed)
        else:
            print(f"⛔ Skipping seed (domain not allowed): {seed}")

    while queue and len(pages) < MAX_PAGES_TOTAL:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)

        # Fetch main content
        try:
            page_data = fetch_page(current)
            if page_data["text"]:
                page_data["id"] = f"page_{len(pages)}"
                pages.append(page_data)
            else:
                print(f"⚠️ Empty text, skipping: {current}")
        except Exception as e:
            print(f"⚠️ Failed to fetch {current}: {e}")
            continue

        # Extract further links from this page
        try:
            r = requests.get(current, timeout=REQUEST_TIMEOUT)
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")

            for a in soup.find_all("a", href=True):
                next_url = normalize_url(current, a["href"])
                if not next_url:
                    continue
                if not is_allowed_url(next_url):
                    continue
                if next_url in visited or next_url in queue:
                    continue
                queue.append(next_url)

        except Exception as e:
            print(f"⚠️ Failed extracting links from {current}: {e}")

    print(f"🔗 Total pages collected: {len(pages)}")
    return pages


# -------------------------
# CHUNKING
# -------------------------

def chunk_document(doc: Dict, chunk_size: int = 800, overlap: int = 100) -> List[Dict]:
    text = doc["text"]
    n = len(text)
    chunks: List[Dict] = []

    if n == 0:
        return chunks

    start = 0
    while start < n:
        end = min(start + chunk_size, n)
        chunks.append({
            "id": f"{doc['id']}_{start}_{end}",
            "title": doc["title"],
            "url": doc["url"],
            "text": text[start:end],
        })
        start += chunk_size - overlap

    return chunks


# -------------------------
# EMBEDDING (HF FEATURE-EXTRACTION)
# -------------------------

def _average_tokens(emb: List[List[float]]) -> List[float]:
    """
    Average over token dimension: emb shape = [num_tokens][dim] -> [dim]
    """
    if not emb:
        return []
    dim = len(emb[0])
    sums = [0.0] * dim
    for token_vec in emb:
        for i in range(dim):
            sums[i] += float(token_vec[i])
    return [v / len(emb) for v in sums]


def embed_text_batch(text_list: List[str]) -> List[List[float]]:
    """
    Uses Hugging Face Inference API feature-extraction pipeline.
    - We call in batches
    - We average token embeddings per text to get a single vector
    """
    if not HF_API_TOKEN:
        raise RuntimeError("HF token not set in Config.hf_token")

    headers = {
        "Authorization": f"Bearer {HF_API_TOKEN}",
        "Content-Type": "application/json",
    }

    all_embeddings: List[List[float]] = []
    BATCH_SIZE = 8  # smaller batch; adjust if needed

    for i in range(0, len(text_list), BATCH_SIZE):
        batch = text_list[i:i + BATCH_SIZE]
        payload = {
            "inputs": batch,
            "model": EMBED_MODEL,
        }

        print(f"🔥 Getting embeddings for batch {i}–{i + len(batch)}")

        r = requests.post(
            "https://api-inference.huggingface.co/pipeline/feature-extraction",
            headers=headers,
            data=json.dumps(payload),
            timeout=90,
        )
        r.raise_for_status()
        data = r.json()

        # HF returns:
        # - single text: [[token_dim...], ...]
        # - list of texts: [ [[token_dim...], ...], [[token_dim...], ...], ... ]
        if isinstance(data, list) and data and isinstance(data[0][0], (int, float, str)):
            # Single text case
            all_embeddings.append(_average_tokens(data))
        else:
            # Batch case
            for seq in data:
                all_embeddings.append(_average_tokens(seq))

    print(f"🧠 Total embeddings created: {len(all_embeddings)}")
    return all_embeddings


# -------------------------
# MAIN BUILD FUNCTION
# -------------------------

def main():
    print("🚀 Starting indexing process...")
    os.makedirs(INDEX_DIR, exist_ok=True)

    # Crawl
    pages = crawl_from_seeds()
    print(f"📄 Pages collected: {len(pages)}")

    for p in pages:
        print(f"   • {p['url']} (len={len(p['text'])})")

    # Chunk
    all_chunks: List[Dict] = []
    for p in pages:
        page_chunks = chunk_document(p)
        print(f"🔹 Chunks from {p['url']}: {len(page_chunks)}")
        all_chunks.extend(page_chunks)

    print(f"📦 Total chunks before embedding: {len(all_chunks)}")

    if not all_chunks:
        print("❌ No chunks created — writing empty index for now.")
        with open(INDEX_FILE, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2)
        return


    # Embed (with error fallback)
    try:
        texts = [c["text"] for c in all_chunks]
        embeddings = embed_text_batch(texts)
    except Exception as e:
        print(f"❌ Embedding failed: {e}")
        print("⚠️ Writing UN-EMBEDDED chunks to index.json for debugging.")
        with open(INDEX_FILE, "w", encoding="utf-8") as f:
            json.dump(all_chunks, f, indent=2)
        return

    # Attach embeddings and save index
    for chunk, emb in zip(all_chunks, embeddings):
        chunk["embedding"] = emb

    with open(INDEX_FILE, "w", encoding="utf-8") as f:
        json.dump(all_chunks, f, indent=2)

    print(f"✅ Index written to {INDEX_FILE}")
    print(f"📌 Final chunk count: {len(all_chunks)}")


# -------------------------
# ENTRYPOINT
# -------------------------

if __name__ == "__main__":
    main()
