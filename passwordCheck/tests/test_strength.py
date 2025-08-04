import hashlib
import secrets
import getpass
from typing import Optional

"""
Utility-Functions for the password handling module
"""


def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, bytes]:
    """
    Create a secure hash of a password with salt

    Args:
        password: the password that is supposed to be hashed in the function
        salt: optional salt (will be generated if not passed)

    Returns a tuple containing the hashed password and the used salt
    """
    if salt is None:
        salt = secrets.token_bytes(32)

    # Usage of PBKDF2 for secure Hashing
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

    return hashed.hex(), salt
