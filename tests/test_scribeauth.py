import os
import re
import unittest
from time import sleep

import pyotp
import pytest
from botocore.awsrequest import AWSRequest
from dotenv import load_dotenv

from scribeauth import (
    MissingIdException,
    ResourceNotFoundException,
    ScribeAuth,
    UnauthorizedException,
)
from scribeauth.scribeauth import Challenge, Tokens

load_dotenv(override=True)

client_id: str = os.environ.get("CLIENT_ID", "")
username: str = os.environ.get("USERNAME", "")
username2: str = os.environ.get("USERNAME2", "")
password: str = os.environ.get("PASSWORD", "")
user_pool_id: str = os.environ.get("USER_POOL_ID", "")
otp = pyotp.TOTP(os.environ.get("OTPCODE", ""))

access = ScribeAuth(client_id=client_id, user_pool_id=user_pool_id)


class TestScribeAuthGetTokensNoMFA:
    def test_get_tokens_username_password_successfully(self):
        user_tokens = access.get_tokens(username=username, password=password)
        assert_tokens(self, user_tokens)

    def test_get_tokens_wrong_username_fails(self):
        with pytest.raises(UnauthorizedException):
            access.get_tokens(username="username", password=password)

    def test_get_tokens_wrong_password_fails(self):
        with pytest.raises(UnauthorizedException):
            access.get_tokens(username=username, password="password")

    def test_get_tokens_refresh_token_successfully(self):
        refresh_token = generate_refresh_token_for_test()
        user_tokens = access.get_tokens(refresh_token=refresh_token)
        user_tokens = assert_tokens(self, user_tokens)
        assert refresh_token == user_tokens.refresh_token

    def test_get_tokens_refresh_token_fails(self):
        with pytest.raises(UnauthorizedException):
            access.get_tokens(refresh_token="refresh_token")

    def test_get_tokens_refresh_token_multiple_params_successfully(self):
        refresh_token = generate_refresh_token_for_test()
        user_tokens = access.get_tokens(refresh_token=refresh_token)
        user_tokens = assert_tokens(self, user_tokens)
        assert refresh_token == user_tokens.refresh_token

    def test_get_tokens_refresh_token_multiple_params_fails(self):
        with pytest.raises(UnauthorizedException):
            access.get_tokens(refresh_token="refresh_token")


class TestScribeAuthGetTokensMFA(unittest.TestCase):
    def test_get_tokens_asks_mfa(self):
        challenge = access.get_tokens(username=username2, password=password)
        assert isinstance(challenge, Challenge)
        assert challenge.challenge_name == "SOFTWARE_TOKEN_MFA"

    def test_get_tokens_username_password_successfully(self):
        challenge = access.get_tokens(username=username2, password=password)
        assert isinstance(challenge, Challenge)
        user_tokens = access.respond_to_auth_challenge_mfa(
            username=username2, session=challenge.session, code=otp.now()
        )
        sleep(61)
        assert_tokens(self, user_tokens)

    def test_get_tokens_refresh_token_successfully(self):
        refresh_token = generate_refresh_token_for_test_with_mfa()
        sleep(61)
        user_tokens = access.get_tokens(refresh_token=refresh_token)
        user_tokens = assert_tokens(self, user_tokens)
        self.assertEqual(refresh_token, user_tokens.refresh_token)

    def test_get_tokens_fails_with_wrong_mfa_code(self):
        challenge = access.get_tokens(username=username2, password=password)
        with self.assertRaises(UnauthorizedException):
            assert isinstance(challenge, Challenge)
            access.respond_to_auth_challenge_mfa(
                username=username2, session=challenge.session, code="000000"
            )

    def test_get_tokens_fails_with_expired_mfa_code(self):
        challenge = access.get_tokens(username=username2, password=password)
        code = otp.now()
        sleep(61)
        with self.assertRaises(UnauthorizedException):
            assert isinstance(challenge, Challenge)
            access.respond_to_auth_challenge_mfa(
                username=username2, session=challenge.session, code=code
            )


class TestScribeAuthRevokeRefreshTokens(unittest.TestCase):
    def test_revoke_refresh_token_successfully(self):
        refresh_token = generate_refresh_token_for_test()
        self.assertTrue(access.revoke_refresh_token(refresh_token))

    def test_revoke_refresh_token_unexistent_successfully(self):
        self.assertTrue(access.revoke_refresh_token("refresh_token"))

    def test_revoke_refresh_token_and_use_old_refresh_token_fails(self):
        refresh_token = generate_refresh_token_for_test()
        self.assertTrue(access.revoke_refresh_token(refresh_token))
        with self.assertRaises(UnauthorizedException):
            access.get_tokens(refresh_token=refresh_token)

    def test_revoke_refresh_token_invalid_and_use_valid_refresh_token_successfully(
        self,
    ):
        refresh_token = generate_refresh_token_for_test()
        self.assertTrue(access.revoke_refresh_token("refresh_token"))
        user_tokens = access.get_tokens(refresh_token=refresh_token)
        user_tokens = assert_tokens(self, user_tokens)
        self.assertEqual(refresh_token, user_tokens.refresh_token)


def generate_refresh_token_for_test():
    tokens_or_challenge = access.get_tokens(username=username, password=password)
    if isinstance(tokens_or_challenge, Tokens):
        return tokens_or_challenge.refresh_token
    raise Exception("Could not get refresh_token")


def generate_id_token_for_test():
    tokens_or_challenge = access.get_tokens(username=username, password=password)
    if isinstance(tokens_or_challenge, Tokens):
        return tokens_or_challenge.id_token
    raise Exception("Could not get id_token")


def generate_refresh_token_for_test_with_mfa():
    challenge = access.get_tokens(username=username2, password=password)
    assert isinstance(challenge, Challenge)
    return access.respond_to_auth_challenge_mfa(
        username=username2, session=challenge.session, code=otp.now()
    ).refresh_token


def assert_tokens(self, user_tokens: Tokens | Challenge) -> Tokens:
    if isinstance(user_tokens, Challenge):
        pytest.fail()
    assert user_tokens is not None
    assert user_tokens.access_token is not None
    assert user_tokens.id_token is not None
    assert user_tokens.refresh_token != user_tokens.access_token
    assert user_tokens.refresh_token != user_tokens.id_token
    assert user_tokens.id_token != user_tokens.access_token
    return user_tokens
