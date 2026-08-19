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

BASE_DIR = Path(
    __file__
).resolve().parent

DATA_DIR = (
    BASE_DIR
    / "data"
)

HISTORY_FILE = (
    DATA_DIR
    / "history.json"
)


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

            data = json.load(
                file
            )

        if not isinstance(
            data,
            list
        ):

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
        HISTORY_FILE.with_suffix(
            ".tmp"
        )
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

    now = (
        datetime
        .now()
        .astimezone()
    )

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
# CLEAR HISTORY
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

        return (
            f"{date} {time}"
        )

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
# HISTORY STATISTICS
# ==========================================================

def get_history_statistics():

    history = load_history()

    if not history:

        return {

            "total":
                0,

            "analysis":
                0,

            "generated":
                0,

            "average_score":
                0,

            "average_entropy":
                0,

            "very_strong":
                0,

            "strong":
                0,

            "medium":
                0,

            "weak":
                0,

            "very_weak":
                0,

            "best_score":
                0,

            "lowest_score":
                0,

        }

    total = len(
        history
    )

    analysis_count = 0

    generated_count = 0

    scores = []

    entropies = []

    ratings = {

        "VERY STRONG":
            0,

        "STRONG":
            0,

        "MEDIUM":
            0,

        "WEAK":
            0,

        "VERY WEAK":
            0,

    }

    # ======================================================
    # PROCESS RECORDS
    # ======================================================

    for entry in history:

        # ==================================================
        # ACTION
        # ==================================================

        action = str(
            entry.get(
                "action",
                "analysis"
            )
        ).lower()

        if action == "generated":

            generated_count += 1

        else:

            analysis_count += 1

        # ==================================================
        # SCORE
        # ==================================================

        score = entry.get(
            "score",
            0
        )

        try:

            score = float(
                score
            )

            scores.append(
                score
            )

        except (
            TypeError,
            ValueError
        ):

            pass

        # ==================================================
        # ENTROPY
        # ==================================================

        entropy = entry.get(
            "entropy",
            0
        )

        try:

            entropy = float(
                entropy
            )

            entropies.append(
                entropy
            )

        except (
            TypeError,
            ValueError
        ):

            pass

        # ==================================================
        # RATING
        # ==================================================

        rating = str(
            entry.get(
                "rating",
                ""
            )
        ).upper().strip()

        if rating in ratings:

            ratings[
                rating
            ] += 1

    # ======================================================
    # SCORE STATISTICS
    # ======================================================

    if scores:

        average_score = (
            sum(scores)
            /
            len(scores)
        )

        best_score = max(
            scores
        )

        lowest_score = min(
            scores
        )

    else:

        average_score = 0

        best_score = 0

        lowest_score = 0

    # ======================================================
    # ENTROPY STATISTICS
    # ======================================================

    if entropies:

        average_entropy = (
            sum(entropies)
            /
            len(entropies)
        )

    else:

        average_entropy = 0

    # ======================================================
    # RETURN
    # ======================================================

    return {

        "total":
            total,

        "analysis":
            analysis_count,

        "generated":
            generated_count,

        "average_score":
            round(
                average_score,
                2
            ),

        "average_entropy":
            round(
                average_entropy,
                2
            ),

        "very_strong":
            ratings[
                "VERY STRONG"
            ],

        "strong":
            ratings[
                "STRONG"
            ],

        "medium":
            ratings[
                "MEDIUM"
            ],

        "weak":
            ratings[
                "WEAK"
            ],

        "very_weak":
            ratings[
                "VERY WEAK"
            ],

        "best_score":
            round(
                best_score,
                2
            ),

        "lowest_score":
            round(
                lowest_score,
                2
            ),

    }


# ==========================================================
# PRIVACY
# ==========================================================

def history_privacy_note():

    return (
        "Passwords themselves are never stored "
        "in PassGuard history."
    )