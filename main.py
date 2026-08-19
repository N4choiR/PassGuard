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

BOLD = "\033[1m"

GREEN = "\033[92m"

RED = "\033[91m"

YELLOW = "\033[93m"

CYAN = "\033[96m"


# ==========================================================
# HEADER
# ==========================================================

def show_header():

    print()

    print(
        f"{CYAN}{BOLD}"
        "╔══════════════════════════════════════╗"
        f"{RESET}"
    )

    print(
        f"{CYAN}{BOLD}"
        "║          🔐 PASSGUARD               ║"
        f"{RESET}"
    )

    print(
        f"{CYAN}{BOLD}"
        "║     Password Security Analyzer      ║"
        f"{RESET}"
    )

    print(
        f"{CYAN}{BOLD}"
        "╚══════════════════════════════════════╝"
        f"{RESET}"
    )

    print()


# ==========================================================
# SCORE BAR
# ==========================================================

def create_score_bar(score):

    total_blocks = 20


    filled_blocks = round(
        score
        /
        100
        *
        total_blocks
    )


    empty_blocks = (
        total_blocks
        -
        filled_blocks
    )


    if score >= 80:

        color = GREEN

    elif score >= 60:

        color = YELLOW

    else:

        color = RED


    return (

        f"{color}"

        +

        "█" * filled_blocks

        +

        "░" * empty_blocks

        +

        f"{RESET}"

    )


# ==========================================================
# CHECK STATUS
# ==========================================================

def check_status(value):

    if value:

        return (
            f"{GREEN}"
            "✓"
            f"{RESET}"
        )


    return (
        f"{RED}"
        "✗"
        f"{RESET}"
    )


# ==========================================================
# RATING COLOR
# ==========================================================

def get_rating_color(score):

    if score >= 80:

        return GREEN


    if score >= 60:

        return YELLOW


    return RED


# ==========================================================
# FORMAT SEARCH SPACE
# ==========================================================

def format_search_space(value):

    if value == 0:

        return "0"


    return f"{value:.2e}"


# ==========================================================
# SECURITY CHECKS
# ==========================================================

def show_security_checks(
    result,
    password_length
):

    checks = result[
        "checks"
    ]


    print(
        f"{BOLD}"
        "Security Analysis"
        f"{RESET}"
    )


    print(
        "──────────────────────────────────────"
    )


    print(
        f"Length              "
        f"{password_length} characters"
    )


    print(
        f"Uppercase           "
        f"{check_status(checks['uppercase'])}"
    )


    print(
        f"Lowercase           "
        f"{check_status(checks['lowercase'])}"
    )


    print(
        f"Numbers             "
        f"{check_status(checks['numbers'])}"
    )


    print(
        f"Symbols             "
        f"{check_status(checks['symbols'])}"
    )


    print(
        f"Character diversity "
        f"{check_status(checks['diversity'])}"
    )


    print(
        f"Common password     "
        f"{check_status(checks['common'])}"
    )


    print(
        f"Patterns            "
        f"{check_status(checks['patterns'])}"
    )


    print(
        f"Repetition          "
        f"{check_status(checks['repetition'])}"
    )


    print(
        f"Sequences           "
        f"{check_status(checks['sequences'])}"
    )


    print(
        f"Predictability      "
        f"{check_status(checks['predictability'])}"
    )


    # ======================================================
    # OPTIONAL CHECKS
    # ======================================================

    if "keyboard" in checks:

        print(
            f"Keyboard pattern    "
            f"{check_status(checks['keyboard'])}"
        )


    if "leetspeak" in checks:

        print(
            f"Leetspeak           "
            f"{check_status(checks['leetspeak'])}"
        )


    if "year" in checks:

        print(
            f"Year pattern        "
            f"{check_status(checks['year'])}"
        )


# ==========================================================
# RESULT
# ==========================================================

def show_result(result):

    score = result[
        "score"
    ]


    rating = result[
        "rating"
    ]


    rating_color = get_rating_color(
        score
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


    print()


    print(
        f"Strength            "
        f"{create_score_bar(score)}"
        f" {score}/100"
    )


    print()


    print(
        f"Rating: "
        f"{rating_color}{BOLD}"
        f"{rating}"
        f"{RESET}"
    )


# ==========================================================
# DETECTED PATTERNS
# ==========================================================

def show_detected_patterns(result):

    patterns = result[
        "detected_patterns"
    ]


    if not patterns:

        return


    print()


    print(
        f"{BOLD}"
        "Detected patterns"
        f"{RESET}"
    )


    print(
        "──────────────────────────────────────"
    )


    for pattern in patterns:

        print(
            f"{YELLOW}⚠{RESET} "
            f"{pattern}"
        )


# ==========================================================
# RECOMMENDATIONS
# ==========================================================

def show_recommendations(result):

    issues = result[
        "issues"
    ]


    if not issues:

        print()

        print(
            f"{GREEN}{BOLD}"
            "✓ No obvious weaknesses detected."
            f"{RESET}"
        )

        return


    print()


    print(
        f"{BOLD}"
        "Recommendations"
        f"{RESET}"
    )


    print(
        "──────────────────────────────────────"
    )


    # Prevent duplicate recommendations

    shown = set()


    for issue in issues:

        if issue in shown:

            continue


        shown.add(issue)


        print(
            f"{YELLOW}→{RESET} "
            f"{issue}"
        )


# ==========================================================
# MAIN
# ==========================================================

def main():

    show_header()


    # ======================================================
    # INPUT
    # ======================================================

    try:

        password = getpass.getpass(
            "Enter password: "
        )


    except KeyboardInterrupt:

        print()

        print(
            f"{YELLOW}"
            "Operation cancelled."
            f"{RESET}"
        )

        return


    except EOFError:

        print()

        print(
            f"{RED}"
            "Unable to read password input."
            f"{RESET}"
        )

        return


    # ======================================================
    # EMPTY PASSWORD
    # ======================================================

    if not password:

        print()

        print(
            f"{RED}"
            "Password cannot be empty."
            f"{RESET}"
        )

        return


    # ======================================================
    # ANALYZE
    # ======================================================

    analyzer = PasswordAnalyzer(
        password
    )


    result = analyzer.analyze()


    # ======================================================
    # DISPLAY
    # ======================================================

    show_security_checks(
        result,
        len(password)
    )


    show_result(
        result
    )


    show_detected_patterns(
        result
    )


    show_recommendations(
        result
    )


    # ======================================================
    # PRIVACY
    # ======================================================

    print()


    print(
        f"{CYAN}"
        "Privacy: Your password is analyzed "
        "locally and is never stored or sent."
        f"{RESET}"
    )


    print()


# ==========================================================
# ENTRY POINT
# ==========================================================

if __name__ == "__main__":

    main()