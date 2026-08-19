# ==========================================================
# PASSGUARD
# SECURITY REPORT
# ==========================================================

from analyzer import PasswordAnalyzer


class SecurityReport:

    # ======================================================
    # INIT
    # ======================================================

    def __init__(self, password):

        self.password = password

        analyzer = PasswordAnalyzer(password)

        self.result = analyzer.analyze()

    # ======================================================
    # CHECK MARK
    # ======================================================

    def check_mark(self, value):

        return "✓" if value else "✗"

    # ======================================================
    # FORMAT SEARCH SPACE
    # ======================================================

    def format_search_space(self):

        value = self.result["search_space"]

        if value == 0:

            return "0"

        return f"{value:.2e}"

    # ======================================================
    # SECURITY CHECKS
    # ======================================================

    def print_checks(self):

        checks = self.result["checks"]

        print(
            "Security Checks"
        )

        print(
            "─" * 38
        )

        labels = {

            "length":
                "Minimum length",

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
                "Common patterns",

            "repetition":
                "Repetition",

            "sequences":
                "Sequential patterns",

            "predictability":
                "Predictability",

            "keyboard":
                "Keyboard patterns",

            "leetspeak":
                "Leetspeak",

            "year":
                "Year pattern",

        }

        for key, label in labels.items():

            value = checks.get(
                key,
                True
            )

            print(
                f"{self.check_mark(value)} "
                f"{label}"
            )

        print()

    # ======================================================
    # CRACK TIMES
    # ======================================================

    def print_crack_times(self):

        times = self.result[
            "crack_times"
        ]

        print(
            "Attack Resistance"
        )

        print(
            "─" * 38
        )

        print(
            f"{'Online attack':22}"
            f"{times['online']}"
        )

        print(
            f"{'Slow offline attack':22}"
            f"{times['slow_offline']}"
        )

        print(
            f"{'Fast offline attack':22}"
            f"{times['fast_offline']}"
        )

        print(
            f"{'Massive GPU attack':22}"
            f"{times['massive_gpu']}"
        )

        print()

    # ======================================================
    # DETECTED PATTERNS
    # ======================================================

    def print_patterns(self):

        patterns = self.result[
            "detected_patterns"
        ]

        if not patterns:

            return

        print(
            "Detected Patterns"
        )

        print(
            "─" * 38
        )

        for pattern in patterns:

            print(
                f"⚠ {pattern}"
            )

        print()

    # ======================================================
    # RECOMMENDATIONS
    # ======================================================

    def print_recommendations(self):

        issues = self.result[
            "issues"
        ]

        if not issues:

            print(
                "Recommendations"
            )

            print(
                "─" * 38
            )

            print(
                "✓ No improvements required."
            )

            print()

            return

        print(
            "Recommendations"
        )

        print(
            "─" * 38
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

        print()

    # ======================================================
    # VERDICT
    # ======================================================

    def print_verdict(self):

        score = self.result[
            "score"
        ]

        rating = self.result[
            "rating"
        ]

        print(
            "Security Verdict"
        )

        print(
            "─" * 38
        )

        if score >= 80:

            print(
                "✓ Password has strong security"
            )

            print(
                "✓ No major weaknesses detected."
            )

        elif score >= 60:

            print(
                "⚠ Password has reasonable security"
            )

            print(
                "⚠ Consider increasing its length."
            )

        elif score >= 40:

            print(
                "⚠ Password security is moderate."
            )

            print(
                "⚠ Several improvements are recommended."
            )

        else:

            print(
                "✗ Password is vulnerable."
            )

            print(
                "✗ Significant improvements are required."
            )

        print()

        print(
            f"Final rating: {rating}"
        )

        print()

    # ======================================================
    # PRINT REPORT
    # ======================================================

    def print_report(self):

        result = self.result

        print()

        print(
            "╔══════════════════════════════════════╗"
        )

        print(
            "║          🔐 PASSGUARD               ║"
        )

        print(
            "║        SECURITY REPORT              ║"
        )

        print(
            "╚══════════════════════════════════════╝"
        )

        print()

        print(
            "Password Security Report"
        )

        print(
            "═" * 38
        )

        print()

        print(
            f"{'Overall Security':22}"
            f"{result['score']}/100"
        )

        print(
            f"{'Rating':22}"
            f"{result['rating']}"
        )

        print()

        print(
            "Password Metrics"
        )

        print(
            "─" * 38
        )

        print(
            f"{'Length':22}"
            f"{len(self.password)} characters"
        )

        print(
            f"{'Character pool':22}"
            f"{result['character_pool']}"
        )

        print(
            f"{'Entropy':22}"
            f"{result['entropy']} bits"
        )

        print(
            f"{'Search space':22}"
            f"{self.format_search_space()}"
        )

        print(
            f"{'Crack resistance':22}"
            f"{result['crack_resistance']}"
        )

        print()

        self.print_crack_times()

        self.print_checks()

        self.print_patterns()

        self.print_recommendations()

        self.print_verdict()

        print(
            "Privacy"
        )

        print(
            "─" * 38
        )

        print(
            "Your password is analyzed locally."
        )

        print(
            "It is never stored or sent anywhere."
        )

        print()