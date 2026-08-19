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

    print("╔══════════════════════════════════════╗")
    print("║          🔐 PASSGUARD               ║")
    print("║     Password Security Suite         ║")
    print("╚══════════════════════════════════════╝")

    print()


# ==========================================================
# YES / NO
# ==========================================================

def ask_yes_no(question, default=True):

    while True:

        default_text = "Y/n" if default else "y/N"

        answer = input(
            f"{question} [{default_text}]: "
        ).strip().lower()

        if not answer:
            return default

        if answer in ("y", "yes"):
            return True

        if answer in ("n", "no"):
            return False

        print("Please enter Y or N.")


# ==========================================================
# FORMAT SEARCH SPACE
# ==========================================================

def format_search_space(value):

    if not value:
        return "0"

    return f"{value:.2e}"


# ==========================================================
# STRENGTH BAR
# ==========================================================

def strength_bar(score):

    total = 20

    filled = round(score / 5)

    filled = max(
        0,
        min(total, filled)
    )

    return (
        "█" * filled
        +
        "░" * (total - filled)
    )


# ==========================================================
# RATING ICON
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
# SHOW CHECK
# ==========================================================

def show_check(label, value):

    print(
        f"{label:<20}"
        f"{'✓' if value else '✗'}"
    )


# ==========================================================
# SHOW ANALYSIS
# ==========================================================

def show_analysis(result, password):

    checks = result.get("checks", {})

    print()

    print("Security Analysis")
    print(LINE)

    # ======================================================
    # BASIC CHECKS
    # ======================================================

    print(
        f"{'Length':<20}"
        f"{len(password)} characters"
    )

    show_check(
        "Uppercase",
        checks.get("uppercase", False)
    )

    show_check(
        "Lowercase",
        checks.get("lowercase", False)
    )

    show_check(
        "Numbers",
        checks.get("numbers", False)
    )

    show_check(
        "Symbols",
        checks.get("symbols", False)
    )

    show_check(
        "Character diversity",
        checks.get("diversity", False)
    )

    show_check(
        "Common password",
        checks.get("common", True)
    )

    show_check(
        "Patterns",
        checks.get("patterns", True)
    )

    show_check(
        "Repetition",
        checks.get("repetition", True)
    )

    show_check(
        "Sequences",
        checks.get("sequences", True)
    )

    show_check(
        "Predictability",
        checks.get("predictability", True)
    )

    show_check(
        "Keyboard pattern",
        checks.get("keyboard", True)
    )

    show_check(
        "Leetspeak",
        checks.get("leetspeak", True)
    )

    show_check(
        "Year pattern",
        checks.get("year", True)
    )

    # ======================================================
    # ENTROPY
    # ======================================================

    print()

    print(
        f"{'Character pool':<20}"
        f"{result.get('character_pool', 0)}"
    )

    print(
        f"{'Entropy':<20}"
        f"{result.get('entropy', 0)} bits"
    )

    print(
        f"{'Search space':<20}"
        f"{format_search_space(result.get('search_space', 0))}"
    )

    print(
        f"{'Crack resistance':<20}"
        f"{result.get('crack_resistance', 'Unknown')}"
    )

    # ======================================================
    # CRACK TIME
    # ======================================================

    crack_times = result.get(
        "crack_times",
        {}
    )

    if crack_times:

        print()

        print("Crack Time Estimate")
        print(LINE)

        print(
            "Estimated average time to exhaust half "
            "of the search space."
        )

        print()

        print(
            f"{'Online attack':<20}"
            f"{crack_times.get('online', 'Unknown')}"
        )

        print(
            f"{'Slow offline attack':<20}"
            f"{crack_times.get('slow_offline', 'Unknown')}"
        )

        print(
            f"{'Fast offline attack':<20}"
            f"{crack_times.get('fast_offline', 'Unknown')}"
        )

        print(
            f"{'Massive GPU attack':<20}"
            f"{crack_times.get('massive_gpu', 'Unknown')}"
        )

    # ======================================================
    # STRENGTH
    # ======================================================

    score = result.get("score", 0)

    print()

    print("Strength")

    print(
        f"{strength_bar(score)} "
        f"{score}/100"
    )

    rating = result.get(
        "rating",
        "UNKNOWN"
    )

    print()

    print(
        f"Rating: "
        f"{get_rating_icon(rating)} "
        f"{rating}"
    )

    # ======================================================
    # DETECTED PATTERNS
    # ======================================================

    detected = result.get(
        "detected_patterns",
        []
    )

    if detected:

        print()

        print("Detected patterns")
        print(LINE)

        unique_patterns = []

        for pattern in detected:

            if pattern not in unique_patterns:

                unique_patterns.append(
                    pattern
                )

        for pattern in unique_patterns:

            print(
                f"⚠ {pattern}"
            )

    # ======================================================
    # RECOMMENDATIONS
    # ======================================================

    issues = result.get(
        "issues",
        []
    )

    unique_issues = []

    for issue in issues:

        if issue not in unique_issues:

            unique_issues.append(
                issue
            )

    if unique_issues:

        print()

        print("Recommendations")
        print(LINE)

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

    print("Password Analysis")
    print(LINE)

    print(
        "Enter your password."
    )

    print(
        "The password is processed locally."
    )

    print()

    try:

        password = getpass.getpass(
            "Enter password: "
        )

    except KeyboardInterrupt:

        print()
        print()
        print("Operation cancelled.")
        return

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

    show_analysis(
        result,
        password
    )


# ==========================================================
# GENERATOR SETTINGS
# ==========================================================

def get_generator_settings():

    print()

    print("Password Generator")
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

            length = int(value)

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
        (
            use_uppercase,
            use_lowercase,
            use_numbers,
            use_symbols
        )
    ):

        print()

        print(
            "At least one character type "
            "must be enabled."
        )

        return None

    return {
        "length": length,
        "use_uppercase": use_uppercase,
        "use_lowercase": use_lowercase,
        "use_numbers": use_numbers,
        "use_symbols": use_symbols
    }


# ==========================================================
# CREATE GENERATOR
# ==========================================================

def create_generator(settings):

    return PasswordGenerator(
        length=settings["length"],
        use_uppercase=settings["use_uppercase"],
        use_lowercase=settings["use_lowercase"],
        use_numbers=settings["use_numbers"],
        use_symbols=settings["use_symbols"]
    )


# ==========================================================
# ANALYZE GENERATED PASSWORD
# ==========================================================

def analyze_generated_password(password):

    analyzer = PasswordAnalyzer(
        password
    )

    return analyzer.analyze()


# ==========================================================
# GENERATE SINGLE PASSWORD
# ==========================================================

def generate_password():

    settings = get_generator_settings()

    if settings is None:
        return

    try:

        generator = create_generator(
            settings
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

    print("Generated Password")
    print(LINE)

    print(password)

    # ======================================================
    # SECURITY ANALYSIS
    # ======================================================

    result = analyze_generated_password(
        password
    )

    print()

    print("Security Analysis")
    print(LINE)

    print(
        f"{'Length:':<20}"
        f"{len(password)}"
    )

    print(
        f"{'Entropy:':<20}"
        f"{result['entropy']} bits"
    )

    print(
        f"{'Crack resistance:':<20}"
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
# GET PASSWORD COUNT
# ==========================================================

def get_password_count():

    while True:

        value = input(
            "How many passwords [5]: "
        ).strip()

        if not value:

            return 5

        try:

            count = int(value)

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

        return count


# ==========================================================
# GENERATE MULTIPLE PASSWORDS
# ==========================================================

def generate_batch_passwords():

    settings = get_generator_settings()

    if settings is None:
        return

    print()

    count = get_password_count()

    try:

        generator = create_generator(
            settings
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

    print("Generated Passwords")
    print(LINE)

    for index, password in enumerate(
        passwords,
        start=1
    ):

        result = analyze_generated_password(
            password
        )

        rating = result["rating"]
        score = result["score"]

        icon = get_rating_icon(
            rating
        )

        print()

        print(
            f"{index:02d}. {password}"
        )

        print(
            f"    {icon} "
            f"{rating} "
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
# MENU
# ==========================================================

def show_menu():

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


# ==========================================================
# MAIN
# ==========================================================

def main():

    while True:

        show_header()

        show_menu()

        try:

            choice = input(
                "Select option: "
            ).strip()

        except KeyboardInterrupt:

            print()
            print()
            print(
                "Thank you for using PassGuard. 🔐"
            )
            print()
            break

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
        # INVALID OPTION
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