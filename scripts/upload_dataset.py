#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from motor.motor_asyncio import AsyncIOMotorClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from app.config import Config  # noqa: E402


def normalize_dataset(payload: Dict) -> Dict:
    metadata = payload.get("metadata") or {}
    modules = payload.get("modules") or []
    level_keys = metadata.get("levels") or ["level_1", "level_2", "level_3"]
    normalized_levels: Dict[str, Dict] = {}
    label_map = ["A", "B", "C", "D"]
    for level_key in level_keys:
        normalized_levels[level_key] = {"badge": metadata.get("badges", {}).get(level_key, level_key), "modules": {}}
    for module in modules:
        module_id = module.get("module_id")
        module_name = module.get("module_name", module_id)
        if not module_id:
            raise ValueError("module_id missing in dataset module")
        level_map = module.get("levels") or {}
        for level_key, questions in level_map.items():
            if level_key not in normalized_levels:
                normalized_levels[level_key] = {"badge": level_key, "modules": {}}
            norm_questions: List[Dict] = []
            for idx, question in enumerate(questions):
                options = question.get("options") or []
                if len(options) != 4:
                    raise ValueError(f"{module_id} {level_key} question requires 4 options")
                option_map = {label_map[i]: opt for i, opt in enumerate(options)}
                correct_text = question.get("correct_answer") or ""
                match_letter = None
                for letter, text in option_map.items():
                    if text.strip() == correct_text.strip():
                        match_letter = letter
                        break
                if not match_letter:
                    raise ValueError(f"Correct answer does not match any option in {module_id} {level_key}")
                norm_questions.append(
                    {
                        "question_index": question.get("id") or idx,
                        "languages": {
                            "en": {
                                "info": question.get("info", ""),
                                "question": question.get("question", ""),
                                "options": option_map,
                                "correct_option": match_letter,
                                "explanation": question.get("explanation", ""),
                            }
                        },
                    }
                )
            normalized_levels[level_key]["modules"][module_id] = {
                "module_name": module_name,
                "questions": norm_questions[:5],
            }
    return normalized_levels


async def upload_dataset(file_path: Path) -> None:
    data = json.loads(file_path.read_text(encoding="utf-8"))
    levels = normalize_dataset(data)
    dataset_id = data.get("dataset_id") or f"dataset-{int(time.time())}"
    version = data.get("metadata", {}).get("version") or dataset_id
    doc = {
        "dataset_id": dataset_id,
        "version": version,
        "active": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": data.get("metadata", {}).get("generated_by", "uploader"),
        "levels": levels,
    }
    client = AsyncIOMotorClient(Config.mongo_uri)
    collection = client[Config.mongo_db_name]["training_datasets"]
    result = await collection.insert_one(doc)
    await collection.update_many({"_id": {"$ne": result.inserted_id}}, {"$set": {"active": False}})
    await collection.update_one({"_id": result.inserted_id}, {"$set": {"active": True}})
    print(f"Dataset {dataset_id} (version {version}) uploaded and activated.")


def main():
    parser = argparse.ArgumentParser(description="Upload training dataset to MongoDB")
    parser.add_argument("path", type=Path, help="Path to dataset JSON file")
    args = parser.parse_args()
    if not args.path.exists():
        print("File not found:", args.path)
        sys.exit(1)
    asyncio.run(upload_dataset(args.path))


if __name__ == "__main__":
    main()
