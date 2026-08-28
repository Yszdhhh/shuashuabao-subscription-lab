"""
Hardware Fingerprint Matching Engine supporting Component Matching Strategy.
Evaluates MATCH_TWO, MATCH_MOST, and exact fingerprint uniqueness.
"""
from typing import Dict, Tuple


class FingerprintMatcher:
    @staticmethod
    def match_components(
        registered_components: Dict[str, str],
        current_components: Dict[str, str],
        strategy: str = "MATCH_MOST",
    ) -> Tuple[bool, int, int, str]:
        """
        Calculates component similarity without arbitrary hand-waved weights.
        Returns (is_match, matched_count, total_count, reason).
        """
        if not registered_components:
            return True, 0, 0, "NO_REGISTERED_COMPONENTS"

        total = len(registered_components)
        matched = 0

        for key, val in registered_components.items():
            if key in current_components and current_components[key] == val:
                matched += 1

        if strategy == "EXACT":
            is_match = matched == total
        elif strategy == "MATCH_TWO":
            is_match = matched >= 2
        elif strategy == "MATCH_MOST":
            # Strict majority (> 50%)
            is_match = matched > (total / 2.0)
        else:
            is_match = matched == total

        reason = f"Strategy={strategy}: matched {matched}/{total} components"
        return is_match, matched, total, reason
