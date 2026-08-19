# ==========================================================
# PASSGUARD
# SECURITY REPORT GENERATOR
# ==========================================================

import json
import os
from datetime import datetime


# ==========================================================
# REPORT DIRECTORY
# ==========================================================

REPORT_DIRECTORY = "reports"


# ==========================================================
# CREATE REPORT DIRECTORY
# ==========================================================

def ensure_report_directory():

    os.makedirs(
        REPORT_DIRECTORY,
        exist_ok=True
    )


# ==========================================================
# REPORT TIMESTAMP
# ==========================================================

def generate_timestamp():

    return datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )


# ==========================================================
# BUILD REPORT
# ==========================================================

def build_report(password, result):

    checks = result.get(
        "checks",
        {}
    )

    report = {

        "application": {

            "name":
                "PassGuard",

            "version":
                "1.0.0",

            "type":
                "Password Security Analyzer"
        },

        "generated_at":
            datetime.now().isoformat(
                timespec="seconds"
            ),

        "privacy": {

            "processed_locally":
                True,

            "password_stored":
                False,

            "password_sent":
                False,

            "password_included_in_report":
                False
        },

        "summary": {

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

            "entropy":
                result.get(
                    "entropy",
                    0
                ),

            "character_pool":
                result.get(
                    "character_pool",
                    0
                ),

            "search_space":
                result.get(
                    "search_space",
                    0
                )
        },

        "password": {

            "length":
                len(password),

            "uppercase":
                checks.get(
                    "uppercase",
                    False
                ),

            "lowercase":
                checks.get(
                    "lowercase",
                    False
                ),

            "numbers":
                checks.get(
                    "numbers",
                    False
                ),

            "symbols":
                checks.get(
                    "symbols",
                    False
                ),

            "character_diversity":
                checks.get(
                    "diversity",
                    False
                )
        },

        "security_checks":
            checks,

        "crack_times":
            result.get(
                "crack_times",
                {}
            ),

        "detected_patterns":
            result.get(
                "detected_patterns",
                []
            ),

        "recommendations":
            result.get(
                "issues",
                []
            )
    }

    return report


# ==========================================================
# SAVE JSON REPORT
# ==========================================================

def save_json_report(password, result):

    ensure_report_directory()

    report = build_report(
        password,
        result
    )

    timestamp = generate_timestamp()

    filename = (
        f"passguard_report_{timestamp}.json"
    )

    filepath = os.path.join(
        REPORT_DIRECTORY,
        filename
    )

    with open(
        filepath,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )

    return filepath


# ==========================================================
# SAVE TEXT REPORT
# ==========================================================

def save_text_report(password, result):

    ensure_report_directory()

    score = result.get(
        "score",
        0
    )

    rating = result.get(
        "rating",
        "UNKNOWN"
    )

    timestamp = generate_timestamp()

    filename = (
        f"passguard_report_{timestamp}.txt"
    )

    filepath = os.path.join(
        REPORT_DIRECTORY,
        filename
    )

    lines = []

    lines.append(
        "PASSGUARD SECURITY REPORT"
    )

    lines.append(
        "=" * 50
    )

    lines.append("")

    # ------------------------------------------------------
    # APPLICATION
    # ------------------------------------------------------

    lines.append(
        "Application"
    )

    lines.append(
        "-" * 50
    )

    lines.append(
        "Name: PassGuard"
    )

    lines.append(
        "Version: 1.0.0"
    )

    lines.append(
        "Type: Password Security Analyzer"
    )

    lines.append("")

    # ------------------------------------------------------
    # PRIVACY
    # ------------------------------------------------------

    lines.append(
        "Privacy"
    )

    lines.append(
        "-" * 50
    )

    lines.append(
        "Password processed locally: YES"
    )

    lines.append(
        "Password stored: NO"
    )

    lines.append(
        "Password sent anywhere: NO"
    )

    lines.append(
        "Password included in report: NO"
    )

    lines.append("")

    # ------------------------------------------------------
    # SUMMARY
    # ------------------------------------------------------

    lines.append(
        "Security Summary"
    )

    lines.append(
        "-" * 50
    )

    lines.append(
        f"Score: {score}/100"
    )

    lines.append(
        f"Rating: {rating}"
    )

    lines.append(
        f"Entropy: "
        f"{result.get('entropy', 0)} bits"
    )

    lines.append(
        f"Character pool: "
        f"{result.get('character_pool', 0)}"
    )

    search_space = result.get(
        "search_space",
        0
    )

    lines.append(
        f"Search space: "
        f"{search_space:.2e}"
    )

    lines.append(
        f"Crack resistance: "
        f"{result.get('crack_resistance', 'Unknown')}"
    )

    lines.append("")

    # ------------------------------------------------------
    # PASSWORD CHARACTER INFORMATION
    # ------------------------------------------------------

    lines.append(
        "Password Characteristics"
    )

    lines.append(
        "-" * 50
    )

    checks = result.get(
        "checks",
        {}
    )

    lines.append(
        f"Length: "
        f"{len(password)}"
    )

    lines.append(
        f"Uppercase: "
        f"{'YES' if checks.get('uppercase') else 'NO'}"
    )

    lines.append(
        f"Lowercase: "
        f"{'YES' if checks.get('lowercase') else 'NO'}"
    )

    lines.append(
        f"Numbers: "
        f"{'YES' if checks.get('numbers') else 'NO'}"
    )

    lines.append(
        f"Symbols: "
        f"{'YES' if checks.get('symbols') else 'NO'}"
    )

    lines.append(
        f"Character diversity: "
        f"{'YES' if checks.get('diversity') else 'NO'}"
    )

    lines.append("")

    # ------------------------------------------------------
    # SECURITY CHECKS
    # ------------------------------------------------------

    lines.append(
        "Security Checks"
    )

    lines.append(
        "-" * 50
    )

    check_names = {

        "uppercase":
            "Uppercase",

        "lowercase":
            "Lowercase",

        "numbers":
            "Numbers",

        "symbols":
            "Symbols",

        "diversity":
            "Character diversity",

        "common":
            "Common password",

        "patterns":
            "Patterns",

        "repetition":
            "Repetition",

        "sequences":
            "Sequences",

        "predictability":
            "Predictability",

        "keyboard":
            "Keyboard pattern",

        "leetspeak":
            "Leetspeak",

        "year":
            "Year pattern",
    }

    for key, name in check_names.items():

        value = checks.get(
            key,
            False
        )

        status = (
            "PASS"
            if value
            else
            "FAIL"
        )

        lines.append(
            f"{name}: {status}"
        )

    lines.append("")

    # ------------------------------------------------------
    # CRACK TIMES
    # ------------------------------------------------------

    lines.append(
        "Crack Time Estimate"
    )

    lines.append(
        "-" * 50
    )

    crack_names = {

        "online":
            "Online attack",

        "slow_offline":
            "Slow offline attack",

        "fast_offline":
            "Fast offline attack",

        "massive_gpu":
            "Massive GPU attack",
    }

    crack_times = result.get(
        "crack_times",
        {}
    )

    for key, name in crack_names.items():

        lines.append(
            f"{name}: "
            f"{crack_times.get(key, 'Unknown')}"
        )

    # ------------------------------------------------------
    # DETECTED PATTERNS
    # ------------------------------------------------------

    detected = result.get(
        "detected_patterns",
        []
    )

    if detected:

        lines.append("")

        lines.append(
            "Detected Patterns"
        )

        lines.append(
            "-" * 50
        )

        for pattern in detected:

            lines.append(
                f"- {pattern}"
            )

    # ------------------------------------------------------
    # RECOMMENDATIONS
    # ------------------------------------------------------

    issues = result.get(
        "issues",
        []
    )

    if issues:

        lines.append("")

        lines.append(
            "Recommendations"
        )

        lines.append(
            "-" * 50
        )

        unique_issues = []

        for issue in issues:

            if issue not in unique_issues:

                unique_issues.append(
                    issue
                )

        for issue in unique_issues:

            lines.append(
                f"- {issue}"
            )

    # ------------------------------------------------------
    # FOOTER
    # ------------------------------------------------------

    lines.append("")

    lines.append(
        "=" * 50
    )

    lines.append(
        "Generated by PassGuard"
    )

    lines.append(
        "Password Security Suite"
    )

    lines.append(
        "Password itself is never included in this report."
    )

    with open(
        filepath,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "\n".join(lines)
        )

    return filepath