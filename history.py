# ==========================================================
# PASSGUARD
# SECURITY HISTORY
# ==========================================================

import json
from datetime import datetime
from pathlib import Path


# ==========================================================
# PATHS
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"

HISTORY_FILE = DATA_DIR / "history.json"


# ==========================================================
# INITIALIZE STORAGE
# ==========================================================

def initialize_history():

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    if not HISTORY_FILE.exists():

        save_history([])


# ==========================================================
# LOAD HISTORY
# ==========================================================

def load_history():

    initialize_history()

    try:

        with open(
            HISTORY_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        if not isinstance(data, list):

            return []

        return data

    except (
        json.JSONDecodeError,
        OSError
    ):

        return []


# ==========================================================
# SAVE HISTORY
# ==========================================================

def save_history(history):

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    temporary_file = (
        HISTORY_FILE.with_suffix(".tmp")
    )

    with open(
        temporary_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            history,
            file,
            ensure_ascii=False,
            indent=4
        )

    temporary_file.replace(
        HISTORY_FILE
    )


# ==========================================================
# CREATE HISTORY ENTRY
# ==========================================================

def create_history_entry(
    result,
    action="analysis"
):

    now = datetime.now().astimezone()

    checks = result.get(
        "checks",
        {}
    )

    entry = {

        "timestamp":
            now.isoformat(),

        "date":
            now.strftime(
                "%Y-%m-%d"
            ),

        "time":
            now.strftime(
                "%H:%M:%S"
            ),

        "action":
            action,

        "length":
            result.get(
                "length",
                0
            ),

        "character_pool":
            result.get(
                "character_pool",
                0
            ),

        "entropy":
            result.get(
                "entropy",
                0
            ),

        "score":
            result.get(
                "score",
                0
            ),

        "rating":
            result.get(
                "rating",
                "UNKNOWN"
            ),

        "crack_resistance":
            result.get(
                "crack_resistance",
                "Unknown"
            ),

        "checks":
            checks,

        "detected_patterns":
            result.get(
                "detected_patterns",
                []
            ),

        "issues":
            result.get(
                "issues",
                []
            ),

    }

    return entry


# ==========================================================
# ADD HISTORY ENTRY
# ==========================================================

def add_history(
    result,
    action="analysis"
):

    history = load_history()

    entry = create_history_entry(
        result,
        action
    )

    history.append(
        entry
    )

    save_history(
        history
    )

    return entry


# ==========================================================
# DELETE HISTORY
# ==========================================================

def clear_history():

    save_history([])


# ==========================================================
# DELETE LAST ENTRY
# ==========================================================

def delete_last_entry():

    history = load_history()

    if not history:

        return False

    history.pop()

    save_history(
        history
    )

    return True


# ==========================================================
# FORMAT DATE
# ==========================================================

def format_entry_date(entry):

    date = entry.get(
        "date",
        ""
    )

    time = entry.get(
        "time",
        ""
    )

    if date and time:

        return f"{date} {time}"

    timestamp = entry.get(
        "timestamp",
        ""
    )

    return timestamp


# ==========================================================
# GET HISTORY COUNT
# ==========================================================

def get_history_count():

    return len(
        load_history()
    )


# ==========================================================
# GET LATEST HISTORY
# ==========================================================

def get_latest_history(
    limit=10
):

    history = load_history()

    if limit <= 0:

        return []

    return history[
        -limit:
    ][::-1]


# ==========================================================
# PRIVACY
# ==========================================================

def history_privacy_note():

    return (
        "Passwords themselves are never stored "
        "in PassGuard history."
    )