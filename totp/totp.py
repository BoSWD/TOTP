import string
import secrets
from base58 import b58encode

import time
from typing import Optional

# totp time window in seconds
# would go to a config in a real microservice

time_window = 15


def generate_secret() -> str:
    """Returns a random 20-symbol base58 string"""
    alphabet = string.ascii_letters + string.digits
    secret = ''.join(secrets.choice(alphabet) for i in range(14))
    return str(b58encode(secret).decode("utf-8")) + str(int(time.time_ns()) % 9)

# print(generate_secret())

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
        # seconds_since_the_epoch = 9999
    seconds_since_the_epoch = int(seconds_since_the_epoch // time_window)

    code = str(seconds_since_the_epoch)[-4:]

    # code = seconds_since_the_epoch
    # print(code)

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
    # seconds_since_the_epoch = '9999'
    return generate_code(secret, seconds_since_the_epoch) == code
