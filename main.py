# ==========================================================
# PASSGUARD
# PASSWORD SECURITY SUITE
# ==========================================================

import getpass

from analyzer import PasswordAnalyzer
from generator import PasswordGenerator


# ==========================================================
# CONSTANTS
# ==========================================================

LINE = "─" * 38


# ==========================================================
# HEADER
# ==========================================================

def show_header():

    print()

    print(
        "╔══════════════════════════════════════╗"
    )

    print(
        "║          🔐 PASSGUARD               ║"
    )

    print(
        "║     Password Security Suite         ║"
    )

    print(
        "╚══════════════════════════════════════╝"
    )

    print()


# ==========================================================
# YES / NO
# ==========================================================

def ask_yes_no(question, default=True):

    while True:

        default_text = (
            "Y/n"
            if default
            else
            "y/N"
        )

        answer = input(
            f"{question} [{default_text}]: "
        ).strip().lower()

        if not answer:

            return default

        if answer in (
            "y",
            "yes"
        ):

            return True

        if answer in (
            "n",
            "no"
        ):

            return False

        print(
            "Please enter Y or N."
        )


# ==========================================================
# FORMAT SEARCH SPACE
# ==========================================================

def format_search_space(value):

    if value == 0:

        return "0"

    return f"{value:.2e}"


# ==========================================================
# STRENGTH BAR
# ==========================================================

def strength_bar(score):

    total = 20

    filled = round(
        score / 5
    )

    filled = max(
        0,
        min(
            total,
            filled
        )
    )

    return (
        "█" * filled
        +
        "░" * (
            total - filled
        )
    )


# ==========================================================
# SHOW ANALYSIS
# ==========================================================

def show_analysis(result):

    checks = result["checks"]

    print()

    print(
        "Security Analysis"
    )

    print(LINE)

    print(
        f"Length              "
        f"{result['length']} characters"
    )

    print(
        f"Uppercase           "
        f"{'✓' if checks['uppercase'] else '✗'}"
    )

    print(
        f"Lowercase           "
        f"{'✓' if checks['lowercase'] else '✗'}"
    )

    print(
        f"Numbers             "
        f"{'✓' if checks['numbers'] else '✗'}"
    )

    print(
        f"Symbols             "
        f"{'✓' if checks['symbols'] else '✗'}"
    )

    print(
        f"Character diversity "
        f"{'✓' if checks['diversity'] else '✗'}"
    )

    print(
        f"Common password     "
        f"{'✓' if checks['common'] else '✗'}"
    )

    print(
        f"Patterns            "
        f"{'✓' if checks['patterns'] else '✗'}"
    )

    print(
        f"Repetition          "
        f"{'✓' if checks['repetition'] else '✗'}"
    )

    print(
        f"Sequences           "
        f"{'✓' if checks['sequences'] else '✗'}"
    )

    print(
        f"Predictability      "
        f"{'✓' if checks['predictability'] else '✗'}"
    )

    print(
        f"Keyboard pattern    "
        f"{'✓' if checks['keyboard'] else '✗'}"
    )

    print(
        f"Leetspeak           "
        f"{'✓' if checks['leetspeak'] else '✗'}"
    )

    print(
        f"Year pattern        "
        f"{'✓' if checks['year'] else '✗'}"
    )

    # ======================================================
    # ENTROPY
    # ======================================================

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

    # ======================================================
    # CRACK TIME
    # ======================================================

    if "crack_times" in result:

        print()

        print(
            "Crack Time Estimate"
        )

        print(LINE)

        print(
            "Estimated average time to exhaust half "
            "of the search space."
        )

        print()

        crack_times = result[
            "crack_times"
        ]

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

    # ======================================================
    # STRENGTH
    # ======================================================

    print()

    print(
        "Strength"
    )

    print(
        f"{strength_bar(result['score'])} "
        f"{result['score']}/100"
    )

    print()

    print(
        f"Rating: {result['rating']}"
    )

    # ======================================================
    # DETECTED PATTERNS
    # ======================================================

    detected = result[
        "detected_patterns"
    ]

    if detected:

        print()

        print(
            "Detected patterns"
        )

        print(LINE)

        for pattern in detected:

            print(
                f"⚠ {pattern}"
            )

    # ======================================================
    # RECOMMENDATIONS
    # ======================================================

    issues = result[
        "issues"
    ]

    if issues:

        print()

        print(
            "Recommendations"
        )

        print(LINE)

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

    else:

        print()

        print(
            "✓ No obvious weaknesses detected."
        )

    # ======================================================
    # PRIVACY
    # ======================================================

    print()

    print(
        "Privacy: Your password is analyzed "
        "locally and is never stored or sent."
    )

    print()


# ==========================================================
# ANALYZE PASSWORD
# ==========================================================

def analyze_password():

    print()

    print(
        "Password Analysis"
    )

    print(LINE)

    print(
        "Enter your password."
    )

    print(
        "The password is processed locally."
    )

    print()

    password = getpass.getpass(
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

    if "length" not in result:

        result["length"] = len(
            password
        )

    show_analysis(
        result
    )


# ==========================================================
# GENERATOR SETTINGS
# ==========================================================

def get_generator_settings():

    print()

    print(
        "Password Generator"
    )

    print(LINE)

    # ======================================================
    # LENGTH
    # ======================================================

    while True:

        value = input(
            "Password length [16]: "
        ).strip()

        if not value:

            length = 16

            break

        try:

            length = int(
                value
            )

        except ValueError:

            print(
                "Please enter a valid number."
            )

            continue

        if length < 8:

            print(
                "Minimum length is 8."
            )

            continue

        if length > 128:

            print(
                "Maximum length is 128."
            )

            continue

        break

    # ======================================================
    # CHARACTER TYPES
    # ======================================================

    print()

    use_uppercase = ask_yes_no(
        "Use uppercase letters?",
        True
    )

    use_lowercase = ask_yes_no(
        "Use lowercase letters?",
        True
    )

    use_numbers = ask_yes_no(
        "Use numbers?",
        True
    )

    use_symbols = ask_yes_no(
        "Use symbols?",
        True
    )

    if not any(
        [
            use_uppercase,
            use_lowercase,
            use_numbers,
            use_symbols
        ]
    ):

        print()

        print(
            "At least one character type "
            "must be enabled."
        )

        return None

    return {

        "length":
            length,

        "use_uppercase":
            use_uppercase,

        "use_lowercase":
            use_lowercase,

        "use_numbers":
            use_numbers,

        "use_symbols":
            use_symbols

    }


# ==========================================================
# GET RATING ICON
# ==========================================================

def get_rating_icon(rating):

    rating = rating.upper()

    if rating == "VERY STRONG":

        return "🟢"

    if rating == "STRONG":

        return "🟢"

    if rating == "MEDIUM":

        return "🟡"

    if rating == "WEAK":

        return "🟠"

    return "🔴"


# ==========================================================
# GENERATE PASSWORD
# ==========================================================

def generate_password():

    settings = (
        get_generator_settings()
    )

    if settings is None:

        return

    try:

        generator = PasswordGenerator(
            length=settings["length"],
            use_uppercase=settings[
                "use_uppercase"
            ],
            use_lowercase=settings[
                "use_lowercase"
            ],
            use_numbers=settings[
                "use_numbers"
            ],
            use_symbols=settings[
                "use_symbols"
            ],
        )

        password = generator.generate()

    except ValueError as error:

        print()

        print(
            f"Error: {error}"
        )

        return

    # ======================================================
    # DISPLAY PASSWORD
    # ======================================================

    print()

    print(
        "Generated Password"
    )

    print(LINE)

    print(
        password
    )

    # ======================================================
    # ANALYZE GENERATED PASSWORD
    # ======================================================

    analyzer = PasswordAnalyzer(
        password
    )

    result = analyzer.analyze()

    if "length" not in result:

        result["length"] = len(
            password
        )

    print()

    print(
        "Security Analysis"
    )

    print(LINE)

    print(
        f"Length:             "
        f"{result['length']}"
    )

    print(
        f"Entropy:            "
        f"{result['entropy']} bits"
    )

    print(
        f"Crack resistance:   "
        f"{result['crack_resistance']}"
    )

    print()

    print(
        f"Strength: "
        f"{strength_bar(result['score'])} "
        f"{result['score']}/100"
    )

    print()

    print(
        f"Rating: "
        f"{get_rating_icon(result['rating'])} "
        f"{result['rating']}"
    )

    print()

    print(
        "⚠ Keep this password secure."
    )

    print(
        "⚠ PassGuard does not store generated passwords."
    )

    print()


# ==========================================================
# BATCH PASSWORD GENERATOR
# ==========================================================

def generate_batch_passwords():

    settings = (
        get_generator_settings()
    )

    if settings is None:

        return

    # ======================================================
    # COUNT
    # ======================================================

    while True:

        value = input(
            "How many passwords [5]: "
        ).strip()

        if not value:

            count = 5

            break

        try:

            count = int(
                value
            )

        except ValueError:

            print(
                "Please enter a valid number."
            )

            continue

        if count < 1:

            print(
                "Minimum is 1."
            )

            continue

        if count > 50:

            print(
                "Maximum is 50."
            )

            continue

        break

    # ======================================================
    # GENERATOR
    # ======================================================

    try:

        generator = PasswordGenerator(
            length=settings["length"],
            use_uppercase=settings[
                "use_uppercase"
            ],
            use_lowercase=settings[
                "use_lowercase"
            ],
            use_numbers=settings[
                "use_numbers"
            ],
            use_symbols=settings[
                "use_symbols"
            ],
        )

        passwords = generator.generate_many(
            count
        )

    except ValueError as error:

        print()

        print(
            f"Error: {error}"
        )

        return

    # ======================================================
    # RESULTS
    # ======================================================

    print()

    print(
        "Generated Passwords"
    )

    print(LINE)

    for index, password in enumerate(
        passwords,
        start=1
    ):

        analyzer = PasswordAnalyzer(
            password
        )

        result = analyzer.analyze()

        rating = result[
            "rating"
        ]

        score = result[
            "score"
        ]

        icon = get_rating_icon(
            rating
        )

        print()

        print(
            f"{index:02d}. {password}"
        )

        print(
            f"    {icon} {rating} "
            f"({score}/100)"
        )

    # ======================================================
    # PRIVACY
    # ======================================================

    print()

    print(LINE)

    print(
        "Privacy: Generated passwords are "
        "not stored or sent anywhere."
    )

    print()


# ==========================================================
# MAIN MENU
# ==========================================================

def main():

    while True:

        show_header()

        print(
            "1. Analyze Password"
        )

        print(
            "2. Generate Password"
        )

        print(
            "3. Generate Multiple Passwords"
        )

        print(
            "4. Exit"
        )

        print()

        choice = input(
            "Select option: "
        ).strip()

        # ==================================================
        # ANALYZE
        # ==================================================

        if choice == "1":

            analyze_password()

        # ==================================================
        # SINGLE GENERATOR
        # ==================================================

        elif choice == "2":

            generate_password()

        # ==================================================
        # BATCH GENERATOR
        # ==================================================

        elif choice == "3":

            generate_batch_passwords()

        # ==================================================
        # EXIT
        # ==================================================

        elif choice == "4":

            print()

            print(
                "Thank you for using PassGuard. 🔐"
            )

            print()

            break

        # ==================================================
        # INVALID
        # ==================================================

        else:

            print()

            print(
                "Invalid option. "
                "Please select 1, 2, 3 or 4."
            )

            print()


# ==========================================================
# ENTRY POINT
# ==========================================================

if __name__ == "__main__":

    main()