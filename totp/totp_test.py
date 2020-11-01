import unittest
import re
import time
from . import generate_secret, generate_code, time_window, check_code


class TotpMethods(unittest.TestCase):

    def test_generate_secret(self):
        secret = generate_secret()

        def is_base58(ss58_string):
            ss58_match = '^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]*$'
            return re.match(ss58_match, ss58_string)

        # secret should be 20 characters long
        # (an arbitrary number, approx 115 bits of randomness)
        self.assertEqual(len(secret), 20)

        # secret must be a valid base58 string
        self.assertTrue(is_base58(secret))

        # secret must be different for each call
        second_secret = generate_secret()
        self.assertNotEqual(secret, second_secret)

        # secret must also be random, but that's impossible to assert in unit tests,
        # so we leave cheking that for manual review

    def test_generate_code(self):

        long_secret = "aaaaaaaaaaaaaaaaaaaaaaaaa"
        correct_secret = "aaaaaaaaaaaaaaaaaaaa"

        # should raise when secret has wrong format
        with self.assertRaises(ValueError):
            generate_code(long_secret)

        # code must be 4 digits long
        code = generate_code(correct_secret)
        self.assertTrue(code.isnumeric() and len(code) == 4)

        test_time = int(time.time())

        time_within_window = test_time
        if test_time % time_window == 0:
            time_within_window += time_window/2
        else:
            time_within_window -= 1

        time_different_window = test_time + time_window

        # code must be different for different 15s time windows
        # edge case: might be the same but the odds are slim (1/10000)
        code = generate_code(correct_secret, test_time)
        code2 = generate_code(correct_secret, time_different_window)
        self.assertNotEqual(code, code2)

        # code must be the same for any time within 15s window
        code2 = generate_code(correct_secret, time_within_window)
        self.assertEqual(code, code2)

    def test_check_code(self):
        long_secret = "aaaaaaaaaaaaaaaaaaaaaaaaa"
        correct_secret = "aaaaaaaaaaaaaaaaaaaa"
        mock_code = "1234"
        wrong_format_code = "abcde"

        # should raise when secret has wrong format
        with self.assertRaises(ValueError):
            check_code(long_secret, mock_code)

        # check should raise when code is wrong format
        with self.assertRaises(ValueError):
            check_code(correct_secret, wrong_format_code)

        # check should succeed when provided with the current code
        code = generate_code(correct_secret)
        self.assertTrue(check_code(correct_secret, code))

        # check for another moment in time should succeed when provided with code from another time
        previous_window = int(time.time()) - time_window
        code_prev = generate_code(correct_secret, previous_window)
        self.assertTrue(check_code(correct_secret, code_prev, previous_window))

        # check should fail when provided the code from the future
        # edge case: might be the same but the odds are slim (1/10000)
        next_window = int(time.time()) + time_window
        code_next = generate_code(correct_secret, next_window)
        self.assertFalse(check_code(correct_secret, code_next))

        # check should fail when provided with code from the past
        # edge case: might be the same but the odds are slim (1/10000)
        approx_year_ago = int(time.time()) - 365*24*60*60
        code_past = generate_code(correct_secret, approx_year_ago)
        self.assertFalse(check_code(correct_secret, code_past))

        # this test might be flaky on time window edges;
        # better practice would be to mock time source and test with that


if __name__ == '__main__':
    unittest.main()
