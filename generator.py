# ==========================================================
# PASSGUARD
# SECURE PASSWORD GENERATOR
# ==========================================================

import secrets
import string


class PasswordGenerator:

    # ======================================================
    # INIT
    # ======================================================

    def __init__(
        self,
        length=16,
        use_uppercase=True,
        use_lowercase=True,
        use_numbers=True,
        use_symbols=True,
    ):

        self.length = length

        self.use_uppercase = (
            use_uppercase
        )

        self.use_lowercase = (
            use_lowercase
        )

        self.use_numbers = (
            use_numbers
        )

        self.use_symbols = (
            use_symbols
        )

    # ======================================================
    # CHARACTER SET
    # ======================================================

    def get_character_sets(self):

        sets = []

        if self.use_uppercase:

            sets.append(
                string.ascii_uppercase
            )

        if self.use_lowercase:

            sets.append(
                string.ascii_lowercase
            )

        if self.use_numbers:

            sets.append(
                string.digits
            )

        if self.use_symbols:

            sets.append(
                "!@#$%^&*()-_=+[]{}"
            )

        return sets

    # ======================================================
    # VALIDATE
    # ======================================================

    def validate(self):

        if self.length < 8:

            raise ValueError(
                "Password length must be at least 8."
            )

        if self.length > 128:

            raise ValueError(
                "Password length cannot exceed 128."
            )

        sets = (
            self.get_character_sets()
        )

        if not sets:

            raise ValueError(
                "At least one character type must be enabled."
            )

        if self.length < len(sets):

            raise ValueError(
                "Password length is too short for the selected character types."
            )

    # ======================================================
    # SECURE SHUFFLE
    # ======================================================

    def secure_shuffle(self, characters):

        characters = list(
            characters
        )

        for i in range(
            len(characters) - 1,
            0,
            -1
        ):

            j = secrets.randbelow(
                i + 1
            )

            characters[i], characters[j] = (
                characters[j],
                characters[i]
            )

        return "".join(
            characters
        )

    # ======================================================
    # GENERATE
    # ======================================================

    def generate(self):

        self.validate()

        sets = (
            self.get_character_sets()
        )

        # ==================================================
        # GUARANTEE CHARACTER DIVERSITY
        # ==================================================

        password = []

        for character_set in sets:

            character = (
                secrets.choice(
                    character_set
                )
            )

            password.append(
                character
            )

        # ==================================================
        # REMAINING CHARACTERS
        # ==================================================

        all_characters = "".join(
            sets
        )

        remaining = (
            self.length
            -
            len(password)
        )

        for _ in range(
            remaining
        ):

            password.append(
                secrets.choice(
                    all_characters
                )
            )

        # ==================================================
        # SHUFFLE
        # ==================================================

        return self.secure_shuffle(
            password
        )

    # ======================================================
    # GENERATE MANY
    # ======================================================

    def generate_many(
        self,
        count=5
    ):

        if count < 1:

            raise ValueError(
                "Count must be at least 1."
            )

        if count > 100:

            raise ValueError(
                "Count cannot exceed 100."
            )

        return [

            self.generate()

            for _ in range(
                count
            )

        ]


# ==========================================================
# SIMPLE TEST
# ==========================================================

if __name__ == "__main__":

    generator = PasswordGenerator(
        length=16,
        use_uppercase=True,
        use_lowercase=True,
        use_numbers=True,
        use_symbols=True,
    )

    print()
    print(
        "Generated Passwords"
    )
    print(
        "──────────────────────────────────────"
    )

    for password in generator.generate_many(5):

        print(
            password
        )