# ==========================================================
# PASSGUARD
# PASSWORD COMPARATOR
# ==========================================================

from analyzer import PasswordAnalyzer


class PasswordComparator:

    def __init__(self, passwords):

        self.passwords = passwords

    # ======================================================
    # COMPARE
    # ======================================================

    def compare(self):

        results = []

        for index, password in enumerate(
            self.passwords,
            start=1
        ):

            analyzer = PasswordAnalyzer(
                password
            )

            result = analyzer.analyze()

            results.append({

                "index":
                    index,

                "score":
                    result["score"],

                "rating":
                    result["rating"],

                "entropy":
                    result["entropy"],

                "character_pool":
                    result["character_pool"],

                "length":
                    len(password),

                "crack_resistance":
                    result["crack_resistance"],

            })

        results.sort(
            key=lambda item: item["score"],
            reverse=True
        )

        for position, result in enumerate(
            results,
            start=1
        ):

            result["rank"] = position

        return results