# load_questions.py
import csv
import sys
from pathlib import Path
import motor.motor_asyncio
import asyncio
from config import Config

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "app"))

from app.utils.lang import detect_language, translate_text  # type: ignore  # noqa: E402
from app.utils.question_taxonomy import module_metadata  # type: ignore  # noqa: E402

# MongoDB connection from config
MONGO_URI = Config.mongo_uri
MONGO_DB_NAME = Config.mongo_db_name

# MongoDB client and collection
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = client[MONGO_DB_NAME]
questions_collection = db["questions"]

# Map CSV level names to numeric levels
LEVEL_MAP = {
    "Beginner": 1,
    "Intermediate": 2,
    "Advanced": 3
}

def ensure_english(text: str) -> str:
    clean = (text or "").strip()
    if not clean:
        return text
    lang = detect_language(clean)
    if lang and lang != "en":
        translated = translate_text(clean, target_lang="en", source_lang=lang)
        return translated or clean
    return text

async def main():
    print("SCRIPT STARTED ✅")
    print("🔍 Reading questions CSV file...")

    # Path to the CSV file (must be in the project root)
    csv_path = Path("questions.csv")

    if not csv_path.exists():
        raise FileNotFoundError("❌ questions.csv not found in the project root directory.")

    # Read CSV file - handle malformed rows with extra fields
    docs = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)  # Skip header row
        
        # Expected columns: Level, Question, Option A, Option B, Option C, Option D, Answer
        expected_cols = ["Level", "Question", "Option A", "Option B", "Option C", "Option D", "Answer"]
        
        for idx, row in enumerate(reader, start=2):  # Start at 2 (row 1 is header)
            # Skip empty rows
            if not row or not any(row):
                continue
            
            # Handle malformed rows - take only first 7 fields
            if len(row) > 7:
                print(f"⚠️ Warning: Row {idx} has {len(row)} fields, using first 7")
                row = row[:7]
            elif len(row) < 7:
                print(f"⚠️ Warning: Row {idx} has only {len(row)} fields, skipping")
                continue
            
            # Map row to dictionary
            row_dict = dict(zip(expected_cols, row))
            
            question_text = row_dict.get("Question", "").strip()
            if not question_text:
                continue
            question_text = ensure_english(question_text)
            
            level_name = row_dict.get("Level", "").strip()
            level = LEVEL_MAP.get(level_name, 1)  # Default to level 1 if unknown
            
            # Extract options
            options = {}
            for opt_letter in ["A", "B", "C", "D"]:
                opt_key = f"Option {opt_letter}"
                opt_value = row_dict.get(opt_key, "").strip()
                if opt_value:
                    options[opt_letter] = ensure_english(opt_value)
                else:
                    print(f"⚠️ Warning: Missing option {opt_letter} for question {idx}")
                    options[opt_letter] = ensure_english(f"Option {opt_letter} (missing)")
            
            # Find correct option by matching answer text
            answer_text = ensure_english(row_dict.get("Answer", "").strip())
            correct_option = None
            
            # First try exact match
            for opt_key, opt_value in options.items():
                if opt_value == answer_text:
                    correct_option = opt_key
                    break
            
            # If exact match not found, try case-insensitive match
            if not correct_option:
                for opt_key, opt_value in options.items():
                    if opt_value.lower() == answer_text.lower():
                        correct_option = opt_key
                        break
            
            # If still not found, try partial match
            if not correct_option:
                for opt_key, opt_value in options.items():
                    # Check if answer is contained in option or vice versa
                    if (answer_text.lower() in opt_value.lower() or 
                        opt_value.lower() in answer_text.lower()):
                        correct_option = opt_key
                        break
            
            # If still not found, log warning and try to infer
            if not correct_option:
                print(f"⚠️ Warning: Could not match answer for question {idx}")
                print(f"   Question: {question_text[:60]}...")
                print(f"   Answer: {answer_text}")
                print(f"   Options: {options}")
                # Try to find the longest matching option as fallback
                best_match = None
                best_score = 0
                for opt_key, opt_value in options.items():
                    # Simple word overlap scoring
                    answer_words = set(answer_text.lower().split())
                    option_words = set(opt_value.lower().split())
                    overlap = len(answer_words & option_words)
                    if overlap > best_score:
                        best_score = overlap
                        best_match = opt_key
                correct_option = best_match or "A"  # Fallback to A
                print(f"   Selected option {correct_option} as best match")
            
            module, relevant_info, attributes, data_block = module_metadata(
                question_text, answer_text, level
            )
            doc = {
                "number": len(docs) + 1,  # Sequential numbering starting from 1
                "question_text": question_text,
                "answer_text": answer_text,
                "level": level,
                "module": module,
                "relevant_info": relevant_info,
                "attributes": attributes,
                "data": data_block,
                "options": options,
                "correct_option": correct_option
            }
            docs.append(doc)

    if not docs:
        raise ValueError("❌ No questions found in CSV file.")

    # Show statistics
    level_counts = {}
    for doc in docs:
        level = doc["level"]
        level_counts[level] = level_counts.get(level, 0) + 1

    print(f"📄 Loaded {len(docs)} questions from CSV.")
    print(f"📊 Level distribution:")
    for level_name, level_num in sorted(LEVEL_MAP.items(), key=lambda x: x[1]):
        count = level_counts.get(level_num, 0)
        print(f"   {level_name} (Level {level_num}): {count} questions")

    if docs:
        print("🗑 Clearing previous documents from 'questions' collection...")
        await questions_collection.delete_many({})

        print("⬆️ Inserting questions into MongoDB Atlas...")
        result = await questions_collection.insert_many(docs)

        print(f"✅ Done. Inserted {len(result.inserted_ids)} questions.")
    else:
        print("⚠️ No questions detected. Please check the file format.")

# 👇 THIS PART IS CRUCIAL: without this, nothing runs when you call `python load_questions.py`
if __name__ == "__main__":
    asyncio.run(main())
