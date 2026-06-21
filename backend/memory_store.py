import json
import os
import logging
from datetime import datetime
from typing import List, Dict, Any

logger = logging.getLogger("sentinel.memory_store")

MEMORY_FILE = os.path.join(os.path.dirname(__file__), "data", "lessons.json")

def load_memory() -> List[Dict[str, Any]]:
    """
    Loads historical lessons learned from a persistent json file.
    """
    os.makedirs(os.path.dirname(MEMORY_FILE), exist_ok=True)
    if not os.path.exists(MEMORY_FILE):
        # Default initialization lessons
        default_lessons = [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "pattern": "READ_SMS + INTERNET",
                "lesson": "Statically detects standard SMS triggers and direct web sockets.",
                "difficulty": 35
            },
            {
                "timestamp": datetime.utcnow().isoformat(),
                "pattern": "Overlay + Banking UI",
                "lesson": "Intercepts fake Activity bounds overlapping legitimate financial screens.",
                "difficulty": 85
            },
            {
                "timestamp": datetime.utcnow().isoformat(),
                "pattern": "Accessibility + Network Access",
                "lesson": "Unveils keystroke logging exfiltration via SSL-pinned obfuscated backchannels.",
                "difficulty": 91
            }
        ]
        try:
            with open(MEMORY_FILE, "w", encoding="utf-8") as f:
                json.dump(default_lessons, f, indent=2)
            return default_lessons
        except Exception as e:
            logger.error(f"Failed to create default memory file: {e}")
            return []
            
    try:
        with open(MEMORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading memory: {e}")
        return []

def save_memory(lessons: List[Dict[str, Any]]) -> bool:
    """
    Saves list of lessons to memory store.
    """
    try:
        os.makedirs(os.path.dirname(MEMORY_FILE), exist_ok=True)
        with open(MEMORY_FILE, "w", encoding="utf-8") as f:
            json.dump(lessons, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving memory: {e}")
        return False

def append_lesson(pattern: str, lesson: str, difficulty: int) -> List[Dict[str, Any]]:
    """
    Appends a single lesson pattern to store and returns the updated database list.
    """
    lessons = load_memory()
    # Avoid duplicate pattern keys to prevent memory clutter
    if not any(item.get("pattern") == pattern for item in lessons):
        new_lesson = {
            "timestamp": datetime.utcnow().isoformat(),
            "pattern": pattern,
            "lesson": lesson,
            "difficulty": difficulty
        }
        lessons.append(new_lesson)
        save_memory(lessons)
    return lessons
