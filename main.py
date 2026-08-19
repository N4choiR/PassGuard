# ==========================================================
# PASSGUARD
# PASSWORD SECURITY ANALYZER
# ==========================================================

import getpass

from analyzer import PasswordAnalyzer


# ==========================================================
# COLORS
# ==========================================================

RESET = "\033[0m"

GREEN = "\033[92m"

RED = "\033[91m"

YELLOW = "\033[93m"

CYAN = "\033[96m"

BLUE = "\033[94m"

WHITE = "\033[97m"


# ==========================================================
# HEADER
# ==========================================================

def print_header():

    print()

    print(
        "╔══════════════════════════════════════╗"
    )

    print(
        "║          🔐 PASSGUARD               ║"
    )

    print(
        "║     Password Security Analyzer      ║"
    )

    print(
        "╚══════════════════════════════════════╝"
    )

    print()


# ==========================================================
# BOOLEAN DISPLAY
# ==========================================================

def display_boolean(value):

    if value:

        return (
            f"{GREEN}✓{RESET}"
        )

    return (
        f"{RED}✗{RESET}"
    )


# ==========================================================
# STRENGTH BAR
# ==========================================================

def strength_bar(score):

    total_blocks = 20

    filled = round(
        score / 100 * total_blocks
    )

    filled = max(
        0,
        min(
            total_blocks,
            filled
        )
    )

    empty = (
        total_blocks
        -
        filled
    )

    return (
        "█" * filled
        +
        "░" * empty
    )


# ==========================================================
# RATING COLOR
# ==========================================================

def rating_color(rating):

    if rating == "VERY WEAK":

        return RED

    if rating == "WEAK":

        return RED

    if rating == "MEDIUM":

        return YELLOW

    if rating == "STRONG":

        return GREEN

    return GREEN


# ==========================================================
# SEARCH SPACE FORMAT
# ==========================================================

def format_search_space(value):

    if value <= 0:

        return "0"

    return (
        f"{value:.2e}"
    )


# ==========================================================
# SECURITY ANALYSIS
# ==========================================================

def print_analysis(result):

    checks = result["checks"]

    print()

    print(
        "Security Analysis"
    )

    print(
        "──────────────────────────────────────"
    )

    print(
        f"Length              "
        f"{len(password)} characters"
    )

    print(
        f"Uppercase           "
        f"{display_boolean(checks.get('uppercase', False))}"
    )

    print(
        f"Lowercase           "
        f"{display_boolean(checks.get('lowercase', False))}"
    )

    print(
        f"Numbers             "
        f"{display_boolean(checks.get('numbers', False))}"
    )

    print(
        f"Symbols             "
        f"{display_boolean(checks.get('symbols', False))}"
    )

    print(
        f"Character diversity "
        f"{display_boolean(checks.get('diversity', False))}"
    )

    print(
        f"Common password     "
        f"{display_boolean(not checks.get('common', True))}"
    )

    print(
        f"Patterns            "
        f"{display_boolean(not checks.get('patterns', True))}"
    )

    print(
        f"Repetition          "
        f"{display_boolean(not checks.get('repetition', True))}"
    )

    print(
        f"Sequences           "
        f"{display_boolean(not checks.get('sequences', True))}"
    )

    print(
        f"Predictability      "
        f"{display_boolean(not checks.get('predictability', True))}"
    )

    print(
        f"Keyboard pattern    "
        f"{display_boolean(not checks.get('keyboard', True))}"
    )

    print(
        f"Leetspeak           "
        f"{display_boolean(not checks.get('leetspeak', True))}"
    )

    print(
        f"Year pattern        "
        f"{display_boolean(not checks.get('year', True))}"
    )

    print()

    print(
        f"Character pool      "
        f"{result['character_pool']}"
    )

    print(
        f"Entropy             "
        f"{result['entropy']} bits"
    )

    print(
        f"Search space        "
        f"{format_search_space(result['search_space'])}"
    )

    print(
        f"Crack resistance    "
        f"{result['crack_resistance']}"
    )


# ==========================================================
# CRACK TIME
# ==========================================================

def print_crack_times(result):

    crack_times = result[
        "crack_times"
    ]

    print()

    print(
        "Crack Time Estimate"
    )

    print(
        "──────────────────────────────────────"
    )

    print(
        "Estimated average time to exhaust "
        "half of the search space."
    )

    print()

    print(
        f"Online attack       "
        f"{crack_times['online']}"
    )

    print(
        f"Slow offline attack "
        f"{crack_times['slow_offline']}"
    )

    print(
        f"Fast offline attack "
        f"{crack_times['fast_offline']}"
    )

    print(
        f"Massive GPU attack  "
        f"{crack_times['massive_gpu']}"
    )


# ==========================================================
# STRENGTH
# ==========================================================

def print_strength(result):

    score = result[
        "score"
    ]

    rating = result[
        "rating"
    ]

    color = rating_color(
        rating
    )

    print()

    print(
        "Strength"
    )

    print(
        f"{strength_bar(score)} "
        f"{score}/100"
    )

    print()

    print(
        f"Rating: "
        f"{color}{rating}{RESET}"
    )


# ==========================================================
# DETECTED PATTERNS
# ==========================================================

def print_detected_patterns(result):

    patterns = result[
        "detected_patterns"
    ]

    if not patterns:

        return

    print()

    print(
        "Detected patterns"
    )

    print(
        "──────────────────────────────────────"
    )

    for pattern in patterns:

        print(
            f"⚠ {pattern}"
        )


# ==========================================================
# RECOMMENDATIONS
# ==========================================================

def print_recommendations(result):

    issues = result[
        "issues"
    ]

    if not issues:

        print()

        print(
            f"{GREEN}✓ No obvious weaknesses detected.{RESET}"
        )

        return

    print()

    print(
        "Recommendations"
    )

    print(
        "──────────────────────────────────────"
    )

    unique_issues = []

    for issue in issues:

        if issue not in unique_issues:

            unique_issues.append(
                issue
            )

    for issue in unique_issues:

        print(
            f"→ {issue}"
        )


# ==========================================================
# PRIVACY
# ==========================================================

def print_privacy():

    print()

    print(
        "Privacy: Your password is analyzed "
        "locally and is never stored or sent."
    )

    print()


# ==========================================================
# MAIN
# ==========================================================

def main():

    global password

    print_header()

    try:

        password = getpass.getpass(
            "Enter password: "
        )

    except KeyboardInterrupt:

        print()

        print(
            "Analysis cancelled."
        )

        return

    except Exception:

        password = input(
            "Enter password: "
        )

    if not password:

        print()

        print(
            "Password cannot be empty."
        )

        return

    analyzer = PasswordAnalyzer(
        password
    )

    result = analyzer.analyze()

    print_analysis(
        result
    )

    print_crack_times(
        result
    )

    print_strength(
        result
    )

    print_detected_patterns(
        result
    )

    print_recommendations(
        result
    )

    print_privacy()


# ==========================================================
# ENTRY POINT
# ==========================================================

if __name__ == "__main__":

    main()