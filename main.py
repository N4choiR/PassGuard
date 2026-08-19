# ==========================================================
# PASSGUARD
# PASSWORD SECURITY SUITE
# ==========================================================

import getpass

from analyzer import PasswordAnalyzer
from generator import PasswordGenerator

from report import (
    save_json_report,
    save_text_report
)

from history import (
    add_history,
    load_history,
    clear_history,
    delete_last_entry,
    get_history_count,
    format_entry_date,
    history_privacy_note,
    get_history_statistics
)


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

def ask_yes_no(
    question,
    default=True
):

    while True:

        default_text = (
            "Y/n"
            if default
            else
            "y/N"
        )

        try:

            answer = input(
                f"{question} [{default_text}]: "
            ).strip().lower()

        except KeyboardInterrupt:

            print()

            return default

        except EOFError:

            print()

            return default

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

def format_search_space(
    value
):

    if not value:

        return "0"

    try:

        return f"{float(value):.2e}"

    except (
        TypeError,
        ValueError
    ):

        return "0"


# ==========================================================
# STRENGTH BAR
# ==========================================================

def strength_bar(
    score
):

    total = 20

    try:

        score = float(
            score
        )

    except (
        TypeError,
        ValueError
    ):

        score = 0

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
# RATING ICON
# ==========================================================

def get_rating_icon(
    rating
):

    rating = str(
        rating
    ).upper()

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

def show_check(
    label,
    value
):

    print(
        f"{label:<20}"
        f"{'✓' if value else '✗'}"
    )


# ==========================================================
# UNIQUE ITEMS
# ==========================================================

def unique_items(
    items
):

    result = []

    for item in items:

        if item not in result:

            result.append(
                item
            )

    return result


# ==========================================================
# SHOW ANALYSIS
# ==========================================================

def show_analysis(
    result,
    password
):

    checks = result.get(
        "checks",
        {}
    )

    print()

    print(
        "Security Analysis"
    )

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
        checks.get(
            "uppercase",
            False
        )
    )

    show_check(
        "Lowercase",
        checks.get(
            "lowercase",
            False
        )
    )

    show_check(
        "Numbers",
        checks.get(
            "numbers",
            False
        )
    )

    show_check(
        "Symbols",
        checks.get(
            "symbols",
            False
        )
    )

    show_check(
        "Character diversity",
        checks.get(
            "diversity",
            False
        )
    )

    show_check(
        "Common password",
        checks.get(
            "common",
            True
        )
    )

    show_check(
        "Patterns",
        checks.get(
            "patterns",
            True
        )
    )

    show_check(
        "Repetition",
        checks.get(
            "repetition",
            True
        )
    )

    show_check(
        "Sequences",
        checks.get(
            "sequences",
            True
        )
    )

    show_check(
        "Predictability",
        checks.get(
            "predictability",
            True
        )
    )

    show_check(
        "Keyboard pattern",
        checks.get(
            "keyboard",
            True
        )
    )

    show_check(
        "Leetspeak",
        checks.get(
            "leetspeak",
            True
        )
    )

    show_check(
        "Year pattern",
        checks.get(
            "year",
            True
        )
    )

    # ======================================================
    # SECURITY METRICS
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
    # CRACK TIMES
    # ======================================================

    crack_times = result.get(
        "crack_times",
        {}
    )

    if crack_times:

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

    score = result.get(
        "score",
        0
    )

    rating = result.get(
        "rating",
        "UNKNOWN"
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
        f"{get_rating_icon(rating)} "
        f"{rating}"
    )

    # ======================================================
    # DETECTED PATTERNS
    # ======================================================

    detected = unique_items(
        result.get(
            "detected_patterns",
            []
        )
    )

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

    issues = unique_items(
        result.get(
            "issues",
            []
        )
    )

    if issues:

        print()

        print(
            "Recommendations"
        )

        print(LINE)

        for issue in issues:

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

    try:

        password = getpass.getpass(
            "Enter password: "
        )

    except KeyboardInterrupt:

        print()

        print(
            "Operation cancelled."
        )

        return

    except EOFError:

        print()

        print(
            "Operation cancelled."
        )

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

    # ======================================================
    # SAVE HISTORY
    # ======================================================

    try:

        add_history(
            result,
            action="analysis"
        )

    except Exception as error:

        print()

        print(
            f"Warning: Could not save history: {error}"
        )

    show_analysis(
        result,
        password
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
    # PASSWORD LENGTH
    # ======================================================

    while True:

        try:

            value = input(
                "Password length [16]: "
            ).strip()

        except KeyboardInterrupt:

            print()

            print(
                "Operation cancelled."
            )

            return None

        except EOFError:

            print()

            print(
                "Operation cancelled."
            )

            return None

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

    # ======================================================
    # VALIDATION
    # ======================================================

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
# CREATE GENERATOR
# ==========================================================

def create_generator(
    settings
):

    return PasswordGenerator(

        length=settings[
            "length"
        ],

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
        ]

    )


# ==========================================================
# GENERATE PASSWORD
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

    result = PasswordAnalyzer(
        password
    ).analyze()

    # ======================================================
    # SAVE HISTORY
    # ======================================================

    try:

        add_history(
            result,
            action="generated"
        )

    except Exception as error:

        print()

        print(
            f"Warning: Could not save history: {error}"
        )

    print()

    print(
        "Security Analysis"
    )

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
# BATCH GENERATOR
# ==========================================================

def generate_batch_passwords():

    settings = get_generator_settings()

    if settings is None:

        return

    # ======================================================
    # PASSWORD COUNT
    # ======================================================

    while True:

        try:

            value = input(
                "How many passwords [5]: "
            ).strip()

        except KeyboardInterrupt:

            print()

            print(
                "Operation cancelled."
            )

            return

        except EOFError:

            print()

            print(
                "Operation cancelled."
            )

            return

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
    # GENERATE
    # ======================================================

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

    print(
        "Generated Passwords"
    )

    print(LINE)

    for index, password in enumerate(
        passwords,
        start=1
    ):

        result = PasswordAnalyzer(
            password
        ).analyze()

        rating = result[
            "rating"
        ]

        score = result[
            "score"
        ]

        icon = get_rating_icon(
            rating
        )

        # ==================================================
        # SAVE HISTORY
        # ==================================================

        try:

            add_history(
                result,
                action="generated"
            )

        except Exception:

            pass

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
# EXPORT REPORT
# ==========================================================

def export_report():

    print()

    print(
        "Security Report"
    )

    print(LINE)

    print(
        "Analyze a password and export "
        "the security report."
    )

    print()

    # ======================================================
    # PASSWORD INPUT
    # ======================================================

    try:

        password = getpass.getpass(
            "Enter password: "
        )

    except KeyboardInterrupt:

        print()

        print(
            "Operation cancelled."
        )

        return

    except EOFError:

        print()

        print(
            "Operation cancelled."
        )

        return

    if not password:

        print()

        print(
            "Password cannot be empty."
        )

        return

    # ======================================================
    # ANALYSIS
    # ======================================================

    analyzer = PasswordAnalyzer(
        password
    )

    result = analyzer.analyze()

    # ======================================================
    # REPORT FORMAT
    # ======================================================

    print()

    print(
        "Report Format"
    )

    print(LINE)

    print(
        "1. JSON"
    )

    print(
        "2. TXT"
    )

    print(
        "3. JSON + TXT"
    )

    print()

    try:

        choice = input(
            "Select format: "
        ).strip()

    except KeyboardInterrupt:

        print()

        print(
            "Operation cancelled."
        )

        return

    except EOFError:

        print()

        print(
            "Operation cancelled."
        )

        return

    # ======================================================
    # SAVE REPORT
    # ======================================================

    try:

        if choice == "1":

            filepath = save_json_report(
                result
            )

            print()

            print(
                "✓ JSON report created."
            )

            print(
                f"File: {filepath}"
            )

        elif choice == "2":

            filepath = save_text_report(
                result
            )

            print()

            print(
                "✓ Text report created."
            )

            print(
                f"File: {filepath}"
            )

        elif choice == "3":

            json_path = save_json_report(
                result
            )

            txt_path = save_text_report(
                result
            )

            print()

            print(
                "✓ Reports created successfully."
            )

            print()

            print(
                f"JSON: {json_path}"
            )

            print(
                f"TXT:  {txt_path}"
            )

        else:

            print()

            print(
                "Invalid report format."
            )

            return

    except OSError as error:

        print()

        print(
            f"Error creating report: {error}"
        )

        return

    except Exception as error:

        print()

        print(
            f"Unexpected error: {error}"
        )

        return

    # ======================================================
    # PRIVACY
    # ======================================================

    print()

    print(
        "Privacy: The password itself "
        "is never written to the report."
    )

    print()


# ==========================================================
# SHOW HISTORY STATISTICS
# ==========================================================

def show_history_statistics():

    statistics = (
        get_history_statistics()
    )

    total = statistics[
        "total"
    ]

    print()

    print(
        "History Statistics"
    )

    print(LINE)

    if total == 0:

        print(
            "No statistics available."
        )

        print()

        print(
            "Analyze or generate a password first."
        )

        print()

        return

    # ======================================================
    # RECORD COUNTS
    # ======================================================

    print(
        f"{'Total records':<20}"
        f"{statistics['total']}"
    )

    print(
        f"{'Analysis records':<20}"
        f"{statistics['analysis']}"
    )

    print(
        f"{'Generated records':<20}"
        f"{statistics['generated']}"
    )

    # ======================================================
    # AVERAGES
    # ======================================================

    print()

    print(
        f"{'Average score':<20}"
        f"{statistics['average_score']}/100"
    )

    print(
        f"{'Average entropy':<20}"
        f"{statistics['average_entropy']} bits"
    )

    # ======================================================
    # SECURITY RATINGS
    # ======================================================

    print()

    print(
        "Security Ratings"
    )

    print(LINE)

    print(
        f"{'Very Strong':<20}"
        f"{statistics['very_strong']}"
    )

    print(
        f"{'Strong':<20}"
        f"{statistics['strong']}"
    )

    print(
        f"{'Medium':<20}"
        f"{statistics['medium']}"
    )

    print(
        f"{'Weak':<20}"
        f"{statistics['weak']}"
    )

    print(
        f"{'Very Weak':<20}"
        f"{statistics['very_weak']}"
    )

    # ======================================================
    # SCORE OVERVIEW
    # ======================================================

    print()

    print(
        "Score Overview"
    )

    print(LINE)

    print(
        f"{'Best score':<20}"
        f"{statistics['best_score']}/100"
    )

    print(
        f"{'Lowest score':<20}"
        f"{statistics['lowest_score']}/100"
    )

    # ======================================================
    # PRIVACY
    # ======================================================

    print()

    print(
        "Privacy: Passwords themselves are "
        "never stored in statistics."
    )

    print()


# ==========================================================
# SHOW HISTORY
# ==========================================================

def show_history():

    while True:

        print()

        print(
            "Security History"
        )

        print(LINE)

        history = load_history()

        # ==================================================
        # EMPTY HISTORY
        # ==================================================

        if not history:

            print(
                "No security history found."
            )

            print()

            print(
                "Every password analysis will "
                "appear here automatically."
            )

        # ==================================================
        # HISTORY RECORDS
        # ==================================================

        else:

            print(
                f"Total records: {len(history)}"
            )

            print()

            for index, entry in enumerate(
                reversed(history),
                start=1
            ):

                action = entry.get(
                    "action",
                    "analysis"
                )

                if action == "generated":

                    action_text = (
                        "Generated"
                    )

                else:

                    action_text = (
                        "Analysis"
                    )

                rating = entry.get(
                    "rating",
                    "UNKNOWN"
                )

                score = entry.get(
                    "score",
                    0
                )

                entropy = entry.get(
                    "entropy",
                    0
                )

                length = entry.get(
                    "length",
                    0
                )

                crack = entry.get(
                    "crack_resistance",
                    "Unknown"
                )

                icon = get_rating_icon(
                    rating
                )

                print(
                    f"{index:02d}. "
                    f"{format_entry_date(entry)}"
                )

                print(
                    f"    Type: {action_text}"
                )

                print(
                    f"    Length: "
                    f"{length} characters"
                )

                print(
                    f"    Entropy: "
                    f"{entropy} bits"
                )

                print(
                    f"    Strength: "
                    f"{strength_bar(score)} "
                    f"{score}/100"
                )

                print(
                    f"    Rating: "
                    f"{icon} {rating}"
                )

                print(
                    f"    Crack resistance: "
                    f"{crack}"
                )

                patterns = entry.get(
                    "detected_patterns",
                    []
                )

                if patterns:

                    print(
                        "    Patterns:"
                    )

                    for pattern in patterns:

                        print(
                            f"      ⚠ {pattern}"
                        )

                print()

                print(LINE)

            # ==================================================
            # PRIVACY
            # ==================================================

            print()

            print(
                f"Privacy: "
                f"{history_privacy_note()}"
            )

        # ======================================================
        # HISTORY MENU
        # ======================================================

        print()

        print(
            "History Options"
        )

        print(LINE)

        print(
            "1. Back to Main Menu"
        )

        print(
            "2. View Statistics"
        )

        print(
            "3. Delete Last Record"
        )

        print(
            "4. Clear All History"
        )

        print()

        try:

            choice = input(
                "Select option: "
            ).strip()

        except KeyboardInterrupt:

            print()

            return

        except EOFError:

            print()

            return

        # ======================================================
        # BACK
        # ======================================================

        if choice == "1":

            return

        # ======================================================
        # STATISTICS
        # ======================================================

        elif choice == "2":

            show_history_statistics()

            try:

                input(
                    "Press Enter to continue..."
                )

            except (
                KeyboardInterrupt,
                EOFError
            ):

                print()

                return

        # ======================================================
        # DELETE LAST
        # ======================================================

        elif choice == "3":

            if not history:

                print()

                print(
                    "There is no history to delete."
                )

                continue

            confirm = ask_yes_no(
                "Delete the latest history record?",
                False
            )

            if not confirm:

                print()

                print(
                    "Operation cancelled."
                )

                continue

            try:

                deleted = (
                    delete_last_entry()
                )

                if deleted:

                    print()

                    print(
                        "✓ Latest history record deleted."
                    )

                else:

                    print()

                    print(
                        "Could not delete history record."
                    )

            except OSError as error:

                print()

                print(
                    f"Error deleting history: {error}"
                )

        # ======================================================
        # CLEAR ALL
        # ======================================================

        elif choice == "4":

            if not history:

                print()

                print(
                    "History is already empty."
                )

                continue

            print()

            print(
                "⚠ This will permanently delete "
                "all PassGuard history."
            )

            print(
                "⚠ Passwords themselves are not stored."
            )

            print()

            confirm = ask_yes_no(
                "Are you sure?",
                False
            )

            if not confirm:

                print()

                print(
                    "Operation cancelled."
                )

                continue

            try:

                clear_history()

                print()

                print(
                    "✓ All history has been deleted."
                )

            except OSError as error:

                print()

                print(
                    f"Error clearing history: {error}"
                )

        # ======================================================
        # INVALID
        # ======================================================

        else:

            print()

            print(
                "Invalid option."
            )


# ==========================================================
# MAIN MENU
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
        "4. Export Security Report"
    )

    print(
        "5. Security History"
    )

    print(
        "6. Exit"
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

        except EOFError:

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
        # REPORT
        # ==================================================

        elif choice == "4":

            export_report()

        # ==================================================
        # HISTORY
        # ==================================================

        elif choice == "5":

            show_history()

        # ==================================================
        # EXIT
        # ==================================================

        elif choice == "6":

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
                "Please select 1, 2, 3, 4, 5 or 6."
            )

            print()


# ==========================================================
# ENTRY POINT
# ==========================================================

if __name__ == "__main__":

    main()