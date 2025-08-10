import curses.ascii
import math
import string
from typing import Dict, Tuple
from enum import Enum

"""
Password-strenght rating and entropy calculation
"""


class StrengthLevel(Enum):
    # Password Strength Level
    VERY_WEAK = 1
    WEAK = 2
    MEDIUM = 3
    STRONG = 4
    VERY_STRONG = 5


def calculate_entropy(password: str) -> float:
    if not password:
        return 0.0

    charset_size = _get_charset_size(password)
    entropy = len(password) * math.log2(charset_size)

    return entropy


def _get_charset_size(password: str) -> int:
    charset = 0

    if any(c.islower() for c in password):
        charset += 26  # a-z

    if any(c.isupper() for c in password):
        charset += 26  # A-Z

    if any(c.isdigit() for c in password):
        charset += 10  # 0-9

    special_chars = set(string.punctuation)
    if any(c in special_chars for c in password):
        charset += len(special_chars)  # Special-Letters

    return max(charset, 1)  # Must be one so division through 0 wont be a problem
