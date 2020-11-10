# import string
import secrets
import base58
from blake3 import blake3

import time
from typing import Optional

# totp time window in seconds
# would go to a config in a real microservice

time_window = 15


def generate_secret() -> str:
    """Returns a random 20-symbol base58 string"""
    # alphabet = (string.ascii_letters + string.digits).translate({ord(c): '' for c in "0OlI"})
    # secret = ''.join(secrets.choice(alphabet) for i in range(20))

    alphabet = secrets.token_bytes(15)
    secret = base58.b58encode(alphabet).decode('utf-8')[:20]

    return secret

# def generate_secret() -> str:
#     """Returns a random 20-symbol base58 string"""
#     return "abcdeabcdeabcdeabcd" + str(int(time.time_ns()) % 9)


def generate_code(secret: str,
                  seconds_since_the_epoch: Optional[int] = None) -> str:
    """Generates a TOTP code.
    Arguments:
    secret -- 20-symbol base58 string to act as a secret key to make TOTP code
    seconds_since_the_epoch -- second for which to generate. Current moment if None

    Returns 4-digit string that changes every window"""

    if len(secret) > 20:
        raise ValueError("Secret must be 20-symbol base58 string, is '{}' instead".format(secret))

    if seconds_since_the_epoch is None:
        seconds_since_the_epoch = int(time.time())

    seconds_since_the_epoch = int(seconds_since_the_epoch // time_window)
    hash_blk = blake3((secret + str(seconds_since_the_epoch)).encode('utf-8')).hexdigest()
    code = str(int(hash_blk, 16))[-4:]

    return code


def check_code(secret: str, code: str,
               seconds_since_the_epoch: Optional[int] = None) -> bool:
    """Checks if the code is correct for the current moment.
    Arguments:
    secret -- 20-symbol base58 string to act as a secret key to generate TOTP code
    code -- 4-digit string TOTP code.
    seconds_since_the_epoch -- moment at which code should be correct

    Returns True if the code is valid for the provided moment
    """
    if len(code) != 4:
        raise ValueError("TOTP code must be 4 digits string, is '{}' instead".format(code))

    return generate_code(secret, seconds_since_the_epoch) == code
