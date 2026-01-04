#!/usr/bin/env python3
"""
Convert MostAskedQ&A.txt to JSON format with levels.
"""
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "app"))

from app.utils.question_taxonomy import LEVEL_LABEL, module_metadata  # noqa: E402

# Read the file
with open("MostAskedQ&A.txt", "r", encoding="utf-8") as f:
    content = f.read()

# Parse questions and answers
questions = []
lines = content.split('\n')

i = 0
while i < len(lines):
    line = lines[i].strip()
    
    # Look for question pattern: "number. Question text"
    match = re.match(r'^(\d+)\.\s*(.+)$', line)
    if match:
        number = int(match.group(1))
        question_text = match.group(2).strip()
        
        # Get the answer (next non-empty line)
        answer_text = ""
        i += 1
        while i < len(lines) and not lines[i].strip():
            i += 1
        
        if i < len(lines):
            answer_text = lines[i].strip()
        
        # Determine level based on question number
        if number <= 35:
            level = 1  # Basic concepts
        elif number <= 70:
            level = 2  # Intermediate
        else:
            level = 3  # Advanced
        
        module, relevant_info, attributes, data = module_metadata(
            question_text, answer_text, level
        )
        questions.append({
            "number": number,
            "question_text": question_text,
            "answer_text": answer_text,
            "level": level,
            "module": module,
            "relevant_info": relevant_info,
            "attributes": attributes,
            "data": data,
        })
    
    i += 1

# Write to JSON file
output = {
    "questions": questions,
    "total": len(questions),
    "levels": {
        "1": len([q for q in questions if q["level"] == 1]),
        "2": len([q for q in questions if q["level"] == 2]),
        "3": len([q for q in questions if q["level"] == 3])
    }
}

with open('MostAskedQ&A.json', 'w', encoding='utf-8') as f:
    json.dump(output, f, indent=2, ensure_ascii=False)

print(f"✅ Converted {len(questions)} questions to JSON")
print(f"   Level 1: {output['levels']['1']} questions")
print(f"   Level 2: {output['levels']['2']} questions")
print(f"   Level 3: {output['levels']['3']} questions")
print(f"\n📄 Output saved to: MostAskedQ&A.json")
