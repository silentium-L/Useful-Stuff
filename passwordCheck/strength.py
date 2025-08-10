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



