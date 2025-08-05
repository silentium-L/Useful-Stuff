import secrets
import string
from typing import List, Optional

"""
Save Password and Passphrase generator
"""


def generate_password(length: int = 16,
                      required: int = 10,
                      use_uppercase: bool = True,
                      use_lowercase: bool = True,
                      use_digits: bool = True,
                      use_special: bool = True,
                      exclude_ambiguous: bool = True,
                      custom_special: Optional[str] = None) -> str:
    """
    Generate a cryptographic secure password

    :param length: wanted password length
    :param required: required password length (should not be inputted by the user)
    :param use_uppercase: user uppercase letters
    :param use_lowercase: use lowercase letters
    :param use_digits: use digits
    :param use_special: use special letters
    :param exclude_ambiguous: exclude ambiguous characters
    :param custom_special: custom special letters

    returns:
        str: the generated password
    """

    charset = ""

    if length < required:
        raise ValueError("Password to short. It needs to be at least " + str(required) + " characters long")

    # Generate charset that is supposed to be used
    if use_lowercase:
        chars = string.ascii_lowercase
        if exclude_ambiguous:
            chars = chars.replace('1', '').replace('o', '')
        charset += chars
        del chars

    if use_uppercase:
        chars = string.ascii_uppercase
        if exclude_ambiguous:
            chars = chars.replace('I', '').replace('O', '')
        charset += chars
        del chars

    if use_digits:
        chars = string.digits
        if exclude_ambiguous:
            chars = chars.replace('0', '').replace('1', '')
        del chars

    if use_special:
        if custom_special:
            charset += custom_special
        else:
            chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            charset += chars
        del chars

    if not charset:
        raise ValueError("No available characters selected. Generation can't be completed")

    # Generate Password
    password = ''.join(secrets.choice(charset) for _ in range(length))

    # making sure that everything required is used
    password = _ensure_character_types(password, charset, use_uppercase, use_lowercase, use_digits, use_special)

    return password


def _ensure_character_types(password: str, charset: str, use_uppercase: bool, use_lowercase: bool, use_digits: bool,
                            use_special: bool) -> str:
    """
    Checks if all required character types are given
    """

    replacements = []
    checked_password = ''
    password_list = list(password)

    if use_uppercase and not any(c.isupper() for c in password):
        uppercase_chars = [c for c in charset if c.isupper()]
        if uppercase_chars:
            replacements.append(secrets.choice(uppercase_chars))

    if use_lowercase and not any(c.islower() for c in password):
        lowercase_chars = [c for c in charset if c.islower()]
        if lowercase_chars:
            replacements.append(secrets.choice(lowercase_chars))

    if use_digits and not any(c.isdigit() for c in password):
        digit_chars = [c for c in charset if c.isdigit()]
        if digit_chars:
            replacements.append(secrets.choice(digit_chars))

    if use_special and not any(c in string.punctuation for c in password):
        special_chars = [c for c in charset if c in string.punctuation]
        if special_chars:
            replacements.append(secrets.choice(special_chars))

    # generate random position for the replacement
    for replacement in replacements:
        if password_list:  # Only if the password isn't empty
            pos = secrets.randbelow(len(password_list))
            password_list[pos] = replacement

    # recursive call of this function to ensure the replacement didn't destroy the requirement
    checked_password = _ensure_character_types(''.join(password_list), charset, use_uppercase,
                                               use_lowercase, use_digits, use_special)

    return checked_password
