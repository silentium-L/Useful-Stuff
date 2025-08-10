import secrets
import string
from typing import List, Optional

"""
Save Password and Passphrase generator
"""


def generate_password(length: int = 16,
                      min_length: int = 10,
                      use_uppercase: bool = True,
                      use_lowercase: bool = True,
                      use_digits: bool = True,
                      use_special: bool = True,
                      exclude_ambiguous: bool = True,
                      custom_special: Optional[str] = None) -> str:
    """
    Generate a cryptographic secure password

    :param length: wanted password length
    :param min_length: required password length (should not be inputted by the user)
    :param use_uppercase: use uppercase letters
    :param use_lowercase: use lowercase letters
    :param use_digits: use digits
    :param use_special: use special letters
    :param exclude_ambiguous: exclude ambiguous characters (l, o, I, O, 0, 1)
    :param custom_special: custom special letters

    returns:
        str: the generated password
    """

    charset = ""

    if length < min_length:
        raise ValueError(f"Password too short. It needs to be at least {str(min_length)} characters long")

    # Generate charset that is supposed to be used
    if use_lowercase:
        chars = string.ascii_lowercase
        if exclude_ambiguous:
            chars = chars.replace('l', '').replace('o', '')
        charset += chars

    if use_uppercase:
        chars = string.ascii_uppercase
        if exclude_ambiguous:
            chars = chars.replace('I', '').replace('O', '')
        charset += chars

    if use_digits:
        chars = string.digits
        if exclude_ambiguous:
            chars = chars.replace('0', '').replace('1', '')
        charset += chars

    if use_special:
        if custom_special:
            charset += custom_special
        else:
            chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            charset += chars

    if not charset:
        raise ValueError("No available characters selected. Generation can't be completed")

    # Generate Password
    password = ''.join(secrets.choice(charset) for _ in range(length))

    # making sure that everything required is used
    password = _ensure_character_types(password, charset, use_uppercase, use_lowercase, use_digits, use_special)

    return password


def generate_passphrase(num_words: int = 4,
                        separator: str = '-',
                        capitalize: bool = True,
                        add_numbers: bool = True) -> str:
    """
    Generating a secure passphrase (xkcd-Style)

    :param num_words: Amount of words
    :param separator: Used separator between words
    :param capitalize: Capitalize first letter of a word
    :param add_numbers: Add random numbers
    :return: generated passphrase
    """

    selected_words = []

    # Simple Wordlist. Should be replaced for a real case use -- Maybe with a external word source if needed
    words = [
        "apfel", "baum", "computer", "drache", "elefant", "feuer", "garten",
        "haus", "insel", "jacke", "katze", "lampe", "maus", "nacht", "ozean",
        "pferd", "quelle", "regen", "sonne", "tiger", "uhr", "vogel", "wasser",
        "xylophon", "yacht", "zebra", "blume", "brief", "buch", "dach", "fisch"
    ]

    for _ in range(num_words):
        word = secrets.choice(words)
        if capitalize:
            word = word.capitalize()
        selected_words.append(word)

    passphrase = separator.join(selected_words)

    if add_numbers:
        # add 1-2 random numbers
        num_count = secrets.randbelow(2) + 1
        numbers = ''.join(str(secrets.randbelow(10)) for _ in range(num_count))
        passphrase += separator + numbers

    return passphrase


def generate_secure_token(length: int = 32) -> str:
    """
    Generation of a cryptographic secure Token (URL-Safe)

    :param length: Desired Token length
    :return: URL-Safe Token
    """
    return secrets.token_urlsafe(length)


def _ensure_character_types(password: str, charset: str, use_uppercase: bool, use_lowercase: bool, use_digits: bool,
                            use_special: bool) -> str:
    """
    Checks if all required character types are given
    """

    replacements_needed = []
    password_list = list(password)

    if use_uppercase and not any(c.isupper() for c in password):
        uppercase_chars = [c for c in charset if c.isupper()]
        if uppercase_chars:
            replacements_needed.append(secrets.choice(uppercase_chars))

    if use_lowercase and not any(c.islower() for c in password):
        lowercase_chars = [c for c in charset if c.islower()]
        if lowercase_chars:
            replacements_needed.append(secrets.choice(lowercase_chars))

    if use_digits and not any(c.isdigit() for c in password):
        digit_chars = [c for c in charset if c.isdigit()]
        if digit_chars:
            replacements_needed.append(secrets.choice(digit_chars))

    if use_special and not any(c in string.punctuation for c in password):
        special_chars = [c for c in charset if c in string.punctuation]
        if special_chars:
            replacements_needed.append(secrets.choice(special_chars))

    # Selection of a definitive Position (No crossings)
    available_positions = list(range(len(password_list)))

    for replacement_char in replacements_needed:
        if available_positions:
            pos = secrets.choice(available_positions)
            available_positions.remove(pos)  # remove position from potentials
            password_list[pos] = replacement_char

    return ''.join(password_list)
