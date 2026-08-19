# ==========================================================
# PASSGUARD
# PASSWORD SECURITY ANALYZER
# ==========================================================

import math
import re


# ==========================================================
# CONSTANTS
# ==========================================================

MIN_RECOMMENDED_LENGTH = 12

ONLINE_GUESSES_PER_SECOND = 100
SLOW_OFFLINE_GUESSES_PER_SECOND = 100_000
FAST_OFFLINE_GUESSES_PER_SECOND = 100_000_000
MASSIVE_GPU_GUESSES_PER_SECOND = 10_000_000_000


# ==========================================================
# COMMON PASSWORDS
# ==========================================================

COMMON_PASSWORDS = {
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "password",
    "password1",
    "password123",
    "qwerty",
    "qwerty123",
    "qwertyuiop",
    "abc123",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "welcome1",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "baseball",
    "master",
    "login",
    "princess",
    "sunshine",
    "superman",
    "passw0rd",
    "p@ssword",
    "p@ssw0rd",
}


# ==========================================================
# KEYBOARD PATTERNS
# ==========================================================

KEYBOARD_PATTERNS = (
    "qwerty",
    "qwertyuiop",
    "asdfgh",
    "asdfghjkl",
    "zxcvbn",
    "zxcvbnm",
    "qaz",
    "wsx",
    "edc",
    "rfv",
    "tgb",
    "yhn",
    "ujm",
    "1qaz",
    "2wsx",
    "3edc",
    "4rfv",
    "5tgb",
    "6yhn",
    "7ujm",
    "8ik",
    "9ol",
)


# ==========================================================
# LEETSPEAK
# ==========================================================

LEET_TRANSLATION = str.maketrans({
    "0": "o",
    "1": "i",
    "2": "z",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
    "!": "i",
})


# ==========================================================
# YEAR RANGES
# ==========================================================

GREGORIAN_YEAR_START = 1900
GREGORIAN_YEAR_END = 2099

SHAMSI_YEAR_START = 1200
SHAMSI_YEAR_END = 1499


# ==========================================================
# PASSWORD ANALYZER
# ==========================================================

class PasswordAnalyzer:

    def __init__(self, password):

        if password is None:
            password = ""

        self.password = str(password)

        self.length = len(
            self.password
        )

    # ======================================================
    # CHARACTER CHECKS
    # ======================================================

    def has_uppercase(self):

        return any(
            character.isupper()
            for character in self.password
        )

    # ------------------------------------------------------

    def has_lowercase(self):

        return any(
            character.islower()
            for character in self.password
        )

    # ------------------------------------------------------

    def has_numbers(self):

        return any(
            character.isdigit()
            for character in self.password
        )

    # ------------------------------------------------------

    def has_symbols(self):

        return any(
            not character.isalnum()
            for character in self.password
        )

    # ======================================================
    # CHARACTER POOL
    # ======================================================

    def character_pool(self):

        pool = 0

        if self.has_lowercase():
            pool += 26

        if self.has_uppercase():
            pool += 26

        if self.has_numbers():
            pool += 10

        if self.has_symbols():
            pool += 32

        return pool

    # ======================================================
    # CHARACTER DIVERSITY
    # ======================================================

    def character_diversity(self):

        if self.length == 0:
            return False

        unique_characters = len(
            set(self.password)
        )

        ratio = (
            unique_characters
            /
            self.length
        )

        return ratio >= 0.60

    # ======================================================
    # COMMON PASSWORD
    # ======================================================

    def is_common_password(self):

        normalized = (
            self.password
            .strip()
            .lower()
        )

        if normalized in COMMON_PASSWORDS:
            return False

        leet_normalized = (
            normalized.translate(
                LEET_TRANSLATION
            )
        )

        if leet_normalized in COMMON_PASSWORDS:
            return False

        return True

    # ======================================================
    # REPETITION
    # ======================================================

    def has_bad_repetition(self):

        if self.length < 4:
            return False

        # aaa
        if re.search(
            r"(.)\1\1",
            self.password
        ):
            return True

        # abab
        if re.search(
            r"(.{2})\1",
            self.password
        ):
            return True

        # abcabc
        if re.search(
            r"(.{3})\1",
            self.password
        ):
            return True

        return False

    # ======================================================
    # SEQUENCE DETECTION
    # ======================================================

    @staticmethod
    def _contains_sequence(text):

        if len(text) < 3:
            return False

        for index in range(
            len(text) - 2
        ):

            a = ord(
                text[index]
            )

            b = ord(
                text[index + 1]
            )

            c = ord(
                text[index + 2]
            )

            if (
                b - a == 1
                and
                c - b == 1
            ):
                return True

            if (
                b - a == -1
                and
                c - b == -1
            ):
                return True

        return False

    # ------------------------------------------------------

    def has_sequence(self):

        lowered = (
            self.password.lower()
        )

        if self._contains_sequence(
            lowered
        ):
            return True

        digits = "".join(
            character
            for character in self.password
            if character.isdigit()
        )

        if self._contains_sequence(
            digits
        ):
            return True

        return False

    # ======================================================
    # PATTERN DETECTION
    # ======================================================

    def has_patterns(self):

        password = (
            self.password.lower()
        )

        if re.fullmatch(
            r"(.+)\1+",
            password
        ):
            return False

        if re.fullmatch(
            r"(.)\1+",
            password
        ):
            return False

        if password.isdigit():
            return False

        if password.isalpha():

            if self.has_sequence():
                return False

        return True

    # ======================================================
    # KEYBOARD PATTERN
    # ======================================================

    def has_keyboard_pattern(self):

        normalized = (
            self.password.lower()
        )

        for pattern in KEYBOARD_PATTERNS:

            if pattern in normalized:
                return False

        reversed_password = (
            normalized[::-1]
        )

        for pattern in KEYBOARD_PATTERNS:

            if pattern in reversed_password:
                return False

        return True

    # ======================================================
    # LEETSPEAK
    # ======================================================

    def has_leetspeak_pattern(self):

        leet_characters = (
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "@",
            "$",
            "!",
        )

        if not any(
            character in self.password
            for character in leet_characters
        ):
            return True

        normalized = (
            self.password
            .lower()
            .translate(
                LEET_TRANSLATION
            )
        )

        if normalized in COMMON_PASSWORDS:
            return False

        leet_common_words = {
            "password",
            "qwerty",
            "welcome",
            "letmein",
            "admin",
            "iloveyou",
            "monkey",
            "dragon",
            "football",
            "master",
            "sunshine",
            "superman",
        }

        for word in leet_common_words:

            if word in normalized:
                return False

        return True

    # ======================================================
    # YEAR DETECTION
    # ======================================================

    def detect_year(self):

        matches = re.findall(
            r"(?<!\d)(\d{4})(?!\d)",
            self.password
        )

        for value in matches:

            year = int(value)

            if (
                GREGORIAN_YEAR_START
                <= year
                <= GREGORIAN_YEAR_END
            ):

                return (
                    "Gregorian year pattern: "
                    f"{value}"
                )

            if (
                SHAMSI_YEAR_START
                <= year
                <= SHAMSI_YEAR_END
            ):

                return (
                    "Shamsi year pattern: "
                    f"{value}"
                )

        return None

    # ======================================================
    # YEAR CHECK
    # ======================================================

    def has_year_pattern(self):

        return (
            self.detect_year()
            is None
        )

    # ======================================================
    # PREDICTABILITY
    # ======================================================

    def is_predictable(self):

        password = (
            self.password.lower()
        )

        if not password:
            return True

        if password in COMMON_PASSWORDS:
            return False

        if password.isdigit():
            return False

        if (
            password.isalpha()
            and
            self.has_sequence()
        ):
            return False

        if not self.has_keyboard_pattern():
            return False

        if self.detect_year():
            return False

        date_patterns = (
            r"\d{1,2}[/-]\d{1,2}",
            r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}",
            r"\d{8}",
        )

        for pattern in date_patterns:

            if re.search(
                pattern,
                password
            ):
                return False

        return True

    # ======================================================
    # CHECKS
    # ======================================================

    def build_checks(self):

        return {

            "uppercase":
                self.has_uppercase(),

            "lowercase":
                self.has_lowercase(),

            "numbers":
                self.has_numbers(),

            "symbols":
                self.has_symbols(),

            "diversity":
                self.character_diversity(),

            "common":
                self.is_common_password(),

            "patterns":
                self.has_patterns(),

            "repetition":
                not self.has_bad_repetition(),

            "sequences":
                not self.has_sequence(),

            "predictability":
                self.is_predictable(),

            "keyboard":
                self.has_keyboard_pattern(),

            "leetspeak":
                self.has_leetspeak_pattern(),

            "year":
                self.has_year_pattern(),
        }

    # ======================================================
    # ENTROPY
    # ======================================================

    def calculate_entropy(self, pool):

        if self.length == 0:
            return 0.0

        if pool <= 0:
            return 0.0

        entropy = (
            self.length
            *
            math.log2(pool)
        )

        return round(
            entropy,
            2
        )

    # ======================================================
    # SEARCH SPACE
    # ======================================================

    def calculate_search_space(self, pool):

        if pool <= 0:
            return 0

        return pool ** self.length

    # ======================================================
    # TIME FORMAT
    # ======================================================

    @staticmethod
    def format_duration(seconds):

        if seconds < 1:
            return "< 1 second"

        minute = 60
        hour = 60 * minute
        day = 24 * hour
        year = 365.25 * day

        if seconds < minute:

            return (
                f"{seconds:.1f} seconds"
            )

        if seconds < hour:

            return (
                f"{seconds / minute:.1f} minutes"
            )

        if seconds < day:

            return (
                f"{seconds / hour:.1f} hours"
            )

        if seconds < year:

            return (
                f"{seconds / day:.1f} days"
            )

        years = (
            seconds / year
        )

        if years < 1_000:

            return (
                f"{years:.1f} years"
            )

        if years < 1_000_000:

            return (
                f"{years / 1_000:.1f} thousand years"
            )

        if years < 1_000_000_000:

            return (
                f"{years / 1_000_000:.1f} million years"
            )

        if years < 1_000_000_000_000:

            return (
                f"{years / 1_000_000_000:.1f} billion years"
            )

        return (
            f"{years / 1_000_000_000_000:.1f} trillion years"
        )

    # ======================================================
    # CRACK TIMES
    # ======================================================

    def calculate_crack_times(
        self,
        search_space
    ):

        average_guesses = (
            search_space / 2
        )

        return {

            "online":
                self.format_duration(
                    average_guesses
                    /
                    ONLINE_GUESSES_PER_SECOND
                ),

            "slow_offline":
                self.format_duration(
                    average_guesses
                    /
                    SLOW_OFFLINE_GUESSES_PER_SECOND
                ),

            "fast_offline":
                self.format_duration(
                    average_guesses
                    /
                    FAST_OFFLINE_GUESSES_PER_SECOND
                ),

            "massive_gpu":
                self.format_duration(
                    average_guesses
                    /
                    MASSIVE_GPU_GUESSES_PER_SECOND
                ),
        }

    # ======================================================
    # CRACK RESISTANCE
    # ======================================================

    def get_crack_resistance(self, entropy):

        if entropy < 40:
            return "Very Low"

        if entropy < 50:
            return "Low"

        if entropy < 60:
            return "Moderate"

        if entropy < 80:
            return "High"

        return "Very High"

    # ======================================================
    # DETECTED PATTERNS
    # ======================================================

    def get_detected_patterns(self):

        patterns = []

        year = self.detect_year()

        if year:

            patterns.append(
                year
            )

        if self.has_bad_repetition():

            patterns.append(
                "Repeated character or block pattern"
            )

        if self.has_sequence():

            patterns.append(
                "Sequential character pattern"
            )

        if not self.has_keyboard_pattern():

            patterns.append(
                "Keyboard pattern"
            )

        if not self.has_leetspeak_pattern():

            patterns.append(
                "Common password with leetspeak substitution"
            )

        if not self.is_common_password():

            patterns.append(
                "Common password pattern"
            )

        return self.unique_items(
            patterns
        )

    # ======================================================
    # RECOMMENDATIONS
    # ======================================================

    def build_recommendations(
        self,
        checks,
        entropy
    ):

        issues = []

        if self.length < 12:

            issues.append(
                "Password is relatively short."
            )

        elif self.length < 16:

            issues.append(
                "Password could be longer."
            )

        if not checks["uppercase"]:

            issues.append(
                "Add at least one uppercase letter."
            )

        if not checks["lowercase"]:

            issues.append(
                "Add at least one lowercase letter."
            )

        if not checks["numbers"]:

            issues.append(
                "Add at least one number."
            )

        if not checks["symbols"]:

            issues.append(
                "Add at least one symbol."
            )

        if not checks["diversity"]:

            issues.append(
                "Use a more diverse set of characters."
            )

        if not checks["common"]:

            issues.append(
                "Avoid common or easily guessed passwords."
            )

        if not checks["patterns"]:

            issues.append(
                "Avoid predictable password patterns."
            )

        if not checks["repetition"]:

            issues.append(
                "Avoid excessive character or block repetition."
            )

        if not checks["sequences"]:

            issues.append(
                "Avoid sequential characters such as abc or 123."
            )

        if not checks["predictability"]:

            issues.append(
                "Password contains predictable information."
            )

        if not checks["keyboard"]:

            issues.append(
                "Avoid keyboard patterns such as qwerty or asdf."
            )

        if not checks["leetspeak"]:

            issues.append(
                "Leetspeak substitutions do not make common passwords secure."
            )

        if not checks["year"]:

            year = self.detect_year()

            if year:

                if "Shamsi" in year:

                    issues.append(
                        "Password contains a predictable Shamsi year."
                    )

                else:

                    issues.append(
                        "Password contains a predictable year."
                    )

        if entropy < 50:

            issues.append(
                "Overall password entropy is low."
            )

        elif entropy < 60:

            issues.append(
                "Password entropy could be improved."
            )

        return self.unique_items(
            issues
        )

    # ======================================================
    # SCORE
    # ======================================================

    def calculate_score(
        self,
        checks,
        entropy
    ):

        # ==================================================
        # BASE SCORE
        # ==================================================

        score = 0.0

        # ==================================================
        # LENGTH SCORE - 30 POINTS
        # ==================================================

        if self.length >= 20:

            length_score = 30

        elif self.length >= 18:

            length_score = 29

        elif self.length >= 16:

            length_score = 30

        elif self.length >= 14:

            length_score = 27

        elif self.length >= 12:

            length_score = 24

        elif self.length >= 10:

            length_score = 18

        elif self.length >= 8:

            length_score = 12

        elif self.length >= 6:

            length_score = 6

        else:

            length_score = 0

        score += length_score

        # ==================================================
        # CHARACTER TYPES - 25 POINTS
        # ==================================================

        types = sum(
            (
                checks["uppercase"],
                checks["lowercase"],
                checks["numbers"],
                checks["symbols"],
            )
        )

        type_score = {

            4: 25,

            3: 20,

            2: 14,

            1: 7,

            0: 0,
        }.get(
            types,
            0
        )

        score += type_score

        # ==================================================
        # ENTROPY - 25 POINTS
        # ==================================================

        if entropy >= 100:

            entropy_score = 25

        elif entropy >= 90:

            entropy_score = 24

        elif entropy >= 80:

            entropy_score = 23

        elif entropy >= 70:

            entropy_score = 21

        elif entropy >= 60:

            entropy_score = 18

        elif entropy >= 50:

            entropy_score = 14

        elif entropy >= 40:

            entropy_score = 9

        elif entropy >= 30:

            entropy_score = 4

        else:

            entropy_score = 0

        score += entropy_score

        # ==================================================
        # SECURITY CHECKS - 20 POINTS
        # ==================================================

        security_checks = (
            "diversity",
            "common",
            "patterns",
            "repetition",
            "sequences",
            "predictability",
            "keyboard",
            "leetspeak",
            "year",
        )

        passed = sum(
            bool(
                checks.get(
                    name,
                    True
                )
            )
            for name in security_checks
        )

        security_score = round(
            (
                passed
                /
                len(security_checks)
            )
            * 20
        )

        score += security_score

        # ==================================================
        # IMPORTANT PENALTIES
        # ==================================================
        #
        # These are intentionally stronger than normal
        # check failures because common passwords and
        # obvious patterns are much more dangerous than
        # simply missing one character type.
        #

        if not checks["common"]:

            score -= 30

        if not checks["predictability"]:

            score -= 15

        if not checks["keyboard"]:

            score -= 12

        if not checks["sequences"]:

            score -= 10

        if not checks["repetition"]:

            score -= 10

        if not checks["year"]:

            score -= 8

        if not checks["leetspeak"]:

            score -= 8

        if not checks["patterns"]:

            score -= 8

        # ==================================================
        # LENGTH PENALTY
        # ==================================================

        if self.length < 8:

            score -= 15

        elif self.length < 12:

            score -= 8

        # ==================================================
        # ENTROPY PENALTY
        # ==================================================

        if entropy < 40:

            score -= 15

        elif entropy < 50:

            score -= 10

        elif entropy < 60:

            score -= 5

        # ==================================================
        # PERFECT PASSWORD BONUS
        # ==================================================
        #
        # If every security check passes and the password
        # has excellent entropy and length, allow the score
        # to reach 100 naturally.
        #

        all_checks_passed = all(
            bool(
                checks.get(
                    name,
                    False
                )
            )
            for name in security_checks
        )

        if (
            all_checks_passed
            and
            self.length >= 16
            and
            entropy >= 90
        ):

            score = 100

        # ==================================================
        # FINAL LIMIT
        # ==================================================

        score = max(
            0,
            min(
                100,
                round(score)
            )
        )

        return score

    # ======================================================
    # RATING
    # ======================================================

    @staticmethod
    def get_rating(score):

        if score >= 90:

            return "VERY STRONG"

        if score >= 70:

            return "STRONG"

        if score >= 50:

            return "MEDIUM"

        if score >= 30:

            return "WEAK"

        return "VERY WEAK"

    # ======================================================
    # UNIQUE ITEMS
    # ======================================================

    @staticmethod
    def unique_items(items):

        result = []

        for item in items:

            if item not in result:

                result.append(
                    item
                )

        return result

    # ======================================================
    # ANALYZE
    # ======================================================

    def analyze(self):

        checks = (
            self.build_checks()
        )

        pool = (
            self.character_pool()
        )

        entropy = (
            self.calculate_entropy(
                pool
            )
        )

        search_space = (
            self.calculate_search_space(
                pool
            )
        )

        crack_times = (
            self.calculate_crack_times(
                search_space
            )
        )

        crack_resistance = (
            self.get_crack_resistance(
                entropy
            )
        )

        detected_patterns = (
            self.get_detected_patterns()
        )

        issues = (
            self.build_recommendations(
                checks,
                entropy
            )
        )

        score = (
            self.calculate_score(
                checks,
                entropy
            )
        )

        rating = (
            self.get_rating(
                score
            )
        )

        return {

            # ------------------------------------------------
            # BASIC
            # ------------------------------------------------

            "length":
                self.length,

            # ------------------------------------------------
            # CHECKS
            # ------------------------------------------------

            "checks":
                checks,

            # ------------------------------------------------
            # ENTROPY
            # ------------------------------------------------

            "character_pool":
                pool,

            "entropy":
                entropy,

            "search_space":
                search_space,

            # ------------------------------------------------
            # CRACK
            # ------------------------------------------------

            "crack_resistance":
                crack_resistance,

            "crack_times":
                crack_times,

            # ------------------------------------------------
            # SCORE
            # ------------------------------------------------

            "score":
                score,

            "rating":
                rating,

            # ------------------------------------------------
            # PATTERNS
            # ------------------------------------------------

            "detected_patterns":
                detected_patterns,

            # ------------------------------------------------
            # RECOMMENDATIONS
            # ------------------------------------------------

            "issues":
                issues,
        }