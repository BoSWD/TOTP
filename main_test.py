from fastapi.testclient import TestClient
import re
from time import time

from main import app
from totp import time_window, generate_code


client = TestClient(app)


def test_read_main():
    response = client.get("/v1/")
    assert response.status_code == 200
    assert response.json() == {"description": "A Simple FastAPI TOTP Server v1"}


def test_create_user():
    # new user can be created
    response = client.post("/v1/users/create/new_user")
    assert response.status_code == 201
    assert response.json()
    user = response.json()
    assert user['user_id'] == 'new_user'

    # secret needs to be a 20 symbols long base58 string
    assert len(user['totp_secret']) == 20

    def is_base58(ss58_string):
        ss58_match = '^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]*$'
        return re.match(ss58_match, ss58_string)
    assert is_base58(user['totp_secret'])

    # misses since last totp success need to be 0
    assert user['misses_since_success'] == 0

    # creating an existing user should fail
    response_err = client.post("/v1/users/create/new_user")
    assert response_err.status_code == 409


def test_check_totp():
    # setup new user for checks
    response = client.post("/v1/users/create/new_user_for_check")
    user = response.json()
    secret = user['totp_secret']

    # check should error when provided with wrong code format
    response_err = client.put("/v1/users/check_totp/new_user_for_check/abcdef")
    assert response_err.status_code == 400

    # check should succeed when provided with the current code
    code = generate_code(secret)
    response = client.put("/v1/users/check_totp/new_user_for_check/{}".format(code))
    assert response.status_code == 200
    assert response.json()['success']
    assert response.json()['misses_since_success'] == 0

    # check should succeed when provided with the immediately preceding code
    previous_window = int(time()) - time_window
    code = generate_code(secret, previous_window)
    response = client.put("/v1/users/check_totp/new_user_for_check/{}".format(code))
    assert response.status_code == 200
    assert response.json()['success'] is True
    assert response.json()['misses_since_success'] == 0

    # check should fail when provided the code from the future
    # edge case: might be the same but the odds are slim (1/10000)
    next_window = int(time()) + time_window
    code = generate_code(secret, next_window)
    response = client.put("/v1/users/check_totp/new_user_for_check/{}".format(code))
    assert response.status_code == 200
    assert response.json()['success'] is False
    assert response.json()['misses_since_success'] == 1

    # check should fail when provided with code from the past
    # edge case: might be the same but the odds are slim (1/10000)
    past_window = int(time()) - 2*time_window
    code = generate_code(secret, past_window)
    response = client.put("/v1/users/check_totp/new_user_for_check/{}".format(code))
    assert response.status_code == 200
    assert response.json()['success'] is False
    assert response.json()['misses_since_success'] == 2

    # succeding on a check should reset the fail counter
    code = generate_code(secret)
    response = client.put("/v1/users/check_totp/new_user_for_check/{}".format(code))
    assert response.status_code == 200
    assert response.json()['success'] is True
    assert response.json()['misses_since_success'] == 0
