# ==========================================================
# PASSGUARD
# PASSWORD SECURITY ANALYZER
# ==========================================================

import math
import re

from patterns import (
    COMMON_PASSWORDS,
    COMMON_PATTERNS,
    SEQUENTIAL_PATTERNS,
    KEYBOARD_PATTERNS,
    LEET_MAP,
    LEET_PATTERNS,
    MIN_YEAR,
    MAX_YEAR,
    MIN_SHAMSI_YEAR,
    MAX_SHAMSI_YEAR,
)


class PasswordAnalyzer:

    # ======================================================
    # INIT
    # ======================================================

    def __init__(self, password):

        self.password = password

        self.score = 0

        self.issues = []

        self.checks = {}

        self.entropy = 0

        self.penalties = 0

        self.detected_patterns = []

        self.character_pool = 0

        self.search_space = 0

        self.length_score = 0

        self.uppercase_score = 0

        self.lowercase_score = 0

        self.number_score = 0

        self.symbol_score = 0

        self.diversity_score = 0

    # ======================================================
    # ANALYZE
    # ======================================================

    def analyze(self):

        self.check_length()

        self.check_uppercase()

        self.check_lowercase()

        self.check_numbers()

        self.check_symbols()

        self.check_character_diversity()

        self.check_common_password()

        self.check_patterns()

        self.check_repetition()

        self.check_sequences()

        self.check_predictability()

        self.check_keyboard_patterns()

        self.check_leetspeak()

        self.check_year_pattern()

        self.calculate_entropy()

        self.calculate_search_space()

        self.calculate_score()

        return self.get_result()

    # ======================================================
    # LENGTH
    # ======================================================

    def check_length(self):

        length = len(self.password)

        self.checks["length"] = length >= 12

        if length >= 20:

            self.length_score = 30

        elif length >= 16:

            self.length_score = 27

        elif length >= 14:

            self.length_score = 24

        elif length >= 12:

            self.length_score = 20

        elif length >= 10:

            self.length_score = 14

            self.issues.append(
                "Password could be longer."
            )

        elif length >= 8:

            self.length_score = 8

            self.issues.append(
                "Password is relatively short."
            )

        else:

            self.length_score = 0

            self.issues.append(
                "Password is too short."
            )

    # ======================================================
    # UPPERCASE
    # ======================================================

    def check_uppercase(self):

        exists = bool(
            re.search(
                r"[A-Z]",
                self.password
            )
        )

        self.checks["uppercase"] = exists

        if exists:

            self.uppercase_score = 10

        else:

            self.uppercase_score = 0

            self.issues.append(
                "Add at least one uppercase letter."
            )

    # ======================================================
    # LOWERCASE
    # ======================================================

    def check_lowercase(self):

        exists = bool(
            re.search(
                r"[a-z]",
                self.password
            )
        )

        self.checks["lowercase"] = exists

        if exists:

            self.lowercase_score = 10

        else:

            self.lowercase_score = 0

            self.issues.append(
                "Add at least one lowercase letter."
            )

    # ======================================================
    # NUMBERS
    # ======================================================

    def check_numbers(self):

        exists = bool(
            re.search(
                r"\d",
                self.password
            )
        )

        self.checks["numbers"] = exists

        if exists:

            self.number_score = 10

        else:

            self.number_score = 0

            self.issues.append(
                "Add at least one number."
            )

    # ======================================================
    # SYMBOLS
    # ======================================================

    def check_symbols(self):

        exists = bool(
            re.search(
                r"[^A-Za-z0-9]",
                self.password
            )
        )

        self.checks["symbols"] = exists

        if exists:

            self.symbol_score = 10

        else:

            self.symbol_score = 0

            self.issues.append(
                "Add at least one special character."
            )

    # ======================================================
    # CHARACTER DIVERSITY
    # ======================================================

    def check_character_diversity(self):

        groups = 0

        if re.search(
            r"[a-z]",
            self.password
        ):

            groups += 1

        if re.search(
            r"[A-Z]",
            self.password
        ):

            groups += 1

        if re.search(
            r"\d",
            self.password
        ):

            groups += 1

        if re.search(
            r"[^A-Za-z0-9]",
            self.password
        ):

            groups += 1

        self.checks["diversity"] = groups >= 3

        if groups == 4:

            self.diversity_score = 10

        elif groups == 3:

            self.diversity_score = 8

        elif groups == 2:

            self.diversity_score = 5

        else:

            self.diversity_score = 0

    # ======================================================
    # COMMON PASSWORD
    # ======================================================

    def check_common_password(self):

        normalized = (
            self.password
            .lower()
            .strip()
        )

        if normalized in COMMON_PASSWORDS:

            self.checks["common"] = False

            self.penalties += 50

            self.issues.append(
                "This is a commonly used password."
            )

        else:

            self.checks["common"] = True

    # ======================================================
    # COMMON PATTERNS
    # ======================================================

    def check_patterns(self):

        normalized = (
            self.password
            .lower()
        )

        found = False

        for pattern in COMMON_PATTERNS:

            if pattern in normalized:

                found = True

                self.detected_patterns.append(
                    f"Common pattern: {pattern}"
                )

                self.penalties += 20

                self.issues.append(
                    "Password contains a common pattern."
                )

                break

        self.checks["patterns"] = not found

    # ======================================================
    # REPETITION
    # ======================================================

    def check_repetition(self):

        if not self.password:

            self.checks["repetition"] = False

            return

        repeated_match = re.search(
            r"(.)\1{2,}",
            self.password
        )

        repeated = (
            repeated_match is not None
        )

        self.checks["repetition"] = not repeated

        if repeated:

            character = (
                repeated_match.group(1)
            )

            self.detected_patterns.append(
                f"Repeated character: {character}"
            )

            self.penalties += 10

            self.issues.append(
                "Password contains repeated characters."
            )

    # ======================================================
    # SEQUENCES
    # ======================================================

    def check_sequences(self):

        normalized = (
            self.password
            .lower()
        )

        found = False

        for sequence in SEQUENTIAL_PATTERNS:

            if sequence in normalized:

                found = True

                self.detected_patterns.append(
                    f"Sequential pattern: {sequence}"
                )

                self.penalties += 15

                self.issues.append(
                    "Password contains a predictable sequence."
                )

                break

        self.checks["sequences"] = not found

    # ======================================================
    # KEYBOARD PATTERNS
    # ======================================================

    def check_keyboard_patterns(self):

        normalized = (
            self.password
            .lower()
        )

        for pattern in KEYBOARD_PATTERNS:

            if pattern in normalized:

                self.detected_patterns.append(
                    f"Keyboard pattern: {pattern}"
                )

                self.penalties += 15

                self.issues.append(
                    "Password contains a keyboard pattern."
                )

                self.checks["keyboard"] = False

                return

        self.checks["keyboard"] = True

    # ======================================================
    # LEETSPEAK NORMALIZATION
    # ======================================================

    def normalize_leetspeak(self):

        result = []

        for char in self.password.lower():

            result.append(
                LEET_MAP.get(
                    char,
                    char
                )
            )

        return "".join(result)

    # ======================================================
    # LEETSPEAK DETECTION
    # ======================================================

    def check_leetspeak(self):

        normalized = (
            self.normalize_leetspeak()
        )

        original = (
            self.password
            .lower()
        )

        if normalized == original:

            self.checks["leetspeak"] = True

            return

        found = False

        for pattern in LEET_PATTERNS:

            if pattern in normalized:

                found = True

                self.detected_patterns.append(
                    f"Leetspeak pattern: {pattern}"
                )

                self.penalties += 15

                self.issues.append(
                    "Password uses a predictable leetspeak transformation."
                )

                break

        self.checks["leetspeak"] = not found

    # ======================================================
    # YEAR PATTERN
    # ======================================================

    def check_year_pattern(self):

        found_years = re.findall(
            r"(19\d{2}|20\d{2})",
            self.password
        )

        for year in found_years:

            year_number = int(year)

            if (
                MIN_YEAR
                <=
                year_number
                <=
                MAX_YEAR
            ):

                self.detected_patterns.append(
                    f"Year pattern: {year}"
                )

                self.penalties += 10

                self.issues.append(
                    "Password contains a predictable year."
                )

                self.checks["year"] = False

                return

        # ==================================================
        # SHAMSI YEARS
        # ==================================================

        shamsi_years = re.findall(
            r"(13\d{2}|14\d{2})",
            self.password
        )

        for year in shamsi_years:

            year_number = int(year)

            if (
                MIN_SHAMSI_YEAR
                <=
                year_number
                <=
                MAX_SHAMSI_YEAR
            ):

                self.detected_patterns.append(
                    f"Shamsi year pattern: {year}"
                )

                self.penalties += 10

                self.issues.append(
                    "Password contains a predictable year."
                )

                self.checks["year"] = False

                return

        self.checks["year"] = True

    # ======================================================
    # PREDICTABILITY
    # ======================================================

    def check_predictability(self):

        only_numbers = (
            self.password.isdigit()
        )

        only_letters = (
            self.password.isalpha()
        )

        if only_numbers:

            self.checks["predictability"] = False

            self.penalties += 20

            self.issues.append(
                "Password contains only numbers."
            )

        elif only_letters:

            self.checks["predictability"] = False

            self.penalties += 10

            self.issues.append(
                "Password contains only letters."
            )

        else:

            self.checks["predictability"] = True

    # ======================================================
    # CHARACTER POOL
    # ======================================================

    def calculate_character_pool(self):

        pool = 0

        if re.search(
            r"[a-z]",
            self.password
        ):

            pool += 26

        if re.search(
            r"[A-Z]",
            self.password
        ):

            pool += 26

        if re.search(
            r"\d",
            self.password
        ):

            pool += 10

        if re.search(
            r"[^A-Za-z0-9]",
            self.password
        ):

            pool += 32

        self.character_pool = pool

    # ======================================================
    # ENTROPY
    # ======================================================

    def calculate_entropy(self):

        self.calculate_character_pool()

        if self.character_pool == 0:

            self.entropy = 0

            return

        self.entropy = round(

            len(self.password)
            *
            math.log2(
                self.character_pool
            ),

            2
        )

    # ======================================================
    # SEARCH SPACE
    # ======================================================

    def calculate_search_space(self):

        if self.character_pool == 0:

            self.search_space = 0

            return

        self.search_space = (
            self.character_pool
            **
            len(self.password)
        )

    # ======================================================
    # FINAL SCORE
    # ======================================================

    def calculate_score(self):

        # ==================================================
        # LENGTH
        # ==================================================

        if len(self.password) >= 20:

            length_score = 30

        elif len(self.password) >= 16:

            length_score = 27

        elif len(self.password) >= 14:

            length_score = 24

        elif len(self.password) >= 12:

            length_score = 20

        elif len(self.password) >= 10:

            length_score = 14

        elif len(self.password) >= 8:

            length_score = 8

        else:

            length_score = 0

        # ==================================================
        # CHARACTER DIVERSITY
        # ==================================================

        diversity_score = 0

        if re.search(
            r"[a-z]",
            self.password
        ):

            diversity_score += 5

        if re.search(
            r"[A-Z]",
            self.password
        ):

            diversity_score += 5

        if re.search(
            r"\d",
            self.password
        ):

            diversity_score += 5

        if re.search(
            r"[^A-Za-z0-9]",
            self.password
        ):

            diversity_score += 5

        # ==================================================
        # ENTROPY
        # ==================================================

        if self.entropy >= 100:

            entropy_score = 25

        elif self.entropy >= 80:

            entropy_score = 22

        elif self.entropy >= 60:

            entropy_score = 18

        elif self.entropy >= 40:

            entropy_score = 12

        elif self.entropy >= 30:

            entropy_score = 7

        else:

            entropy_score = 0

        # ==================================================
        # PATTERN RESISTANCE
        # ==================================================

        pattern_score = 15

        if not self.checks.get(
            "common",
            True
        ):

            pattern_score -= 6

        if not self.checks.get(
            "patterns",
            True
        ):

            pattern_score -= 3

        if not self.checks.get(
            "keyboard",
            True
        ):

            pattern_score -= 3

        if not self.checks.get(
            "leetspeak",
            True
        ):

            pattern_score -= 2

        if not self.checks.get(
            "year",
            True
        ):

            pattern_score -= 2

        if not self.checks.get(
            "sequences",
            True
        ):

            pattern_score -= 2

        if not self.checks.get(
            "repetition",
            True
        ):

            pattern_score -= 2

        pattern_score = max(
            0,
            pattern_score
        )

        # ==================================================
        # PREDICTABILITY
        # ==================================================

        predictability_score = 10

        if not self.checks.get(
            "predictability",
            True
        ):

            predictability_score -= 7

        # ==================================================
        # RAW SCORE
        # ==================================================

        raw_score = (

            length_score
            +
            diversity_score
            +
            entropy_score
            +
            pattern_score
            +
            predictability_score

        )

        # ==================================================
        # ENTROPY SECURITY FLOOR
        # ==================================================

        if self.entropy < 20:

            self.score = min(
                raw_score,
                10
            )

        elif self.entropy < 30:

            self.score = min(
                raw_score,
                20
            )

        elif self.entropy < 40:

            self.score = min(
                raw_score,
                35
            )

        else:

            self.score = raw_score

        # ==================================================
        # COMMON PASSWORD FLOOR
        # ==================================================

        if not self.checks.get(
            "common",
            True
        ):

            self.score = min(
                self.score,
                25
            )

        # ==================================================
        # VERY SHORT PASSWORD FLOOR
        # ==================================================

        if len(self.password) < 8:

            self.score = min(
                self.score,
                15
            )

        # ==================================================
        # NUMERIC-ONLY PASSWORD FLOOR
        # ==================================================

        if self.password.isdigit():

            self.score = min(
                self.score,
                10
            )

        # ==================================================
        # FINAL LIMIT
        # ==================================================

        self.score = max(
            0,
            min(
                100,
                round(
                    self.score
                )
            )
        )

    # ======================================================
    # CRACK RESISTANCE
    # ======================================================

    def get_crack_resistance(self):

        if self.entropy < 30:

            return "Very low"

        if self.entropy < 50:

            return "Low"

        if self.entropy < 70:

            return "Moderate"

        if self.entropy < 90:

            return "High"

        if self.entropy < 110:

            return "Very high"

        return "Extremely high"

    # ======================================================
    # RATING
    # ======================================================

    def get_rating(self):

        if self.score < 20:

            return "VERY WEAK"

        if self.score < 40:

            return "WEAK"

        if self.score < 60:

            return "MEDIUM"

        if self.score < 80:

            return "STRONG"

        return "VERY STRONG"

    # ======================================================
    # RESULT
    # ======================================================

    def get_result(self):

        return {

            "score":
                self.score,

            "rating":
                self.get_rating(),

            "entropy":
                self.entropy,

            "character_pool":
                self.character_pool,

            "search_space":
                self.search_space,

            "crack_resistance":
                self.get_crack_resistance(),

            "checks":
                self.checks,

            "issues":
                self.issues,

            "detected_patterns":
                self.detected_patterns,

        }