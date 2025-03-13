import datetime
import os
from tarfile import data_filter
from time import sleep

import jwt
import pyotp
import pytest
from dotenv import load_dotenv

from scribeauth import ScribeAuth, UnauthorizedException
from scribeauth.scribeauth import (
    Challenge,
    SelfManagedSigner,
    Tokens,
    decode_self_signed_jwt,
)

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


class TestScribeAuthGetTokensMFA:
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
        assert refresh_token == user_tokens.refresh_token

    def test_get_tokens_fails_with_wrong_mfa_code(self):
        challenge = access.get_tokens(username=username2, password=password)
        with pytest.raises(UnauthorizedException):
            assert isinstance(challenge, Challenge)
            access.respond_to_auth_challenge_mfa(
                username=username2, session=challenge.session, code="000000"
            )

    def test_get_tokens_fails_with_expired_mfa_code(self):
        challenge = access.get_tokens(username=username2, password=password)
        code = otp.now()
        sleep(61)
        with pytest.raises(UnauthorizedException):
            assert isinstance(challenge, Challenge)
            access.respond_to_auth_challenge_mfa(
                username=username2, session=challenge.session, code=code
            )


class TestScribeAuthRevokeRefreshTokens:
    def test_revoke_refresh_token_successfully(self):
        refresh_token = generate_refresh_token_for_test()

        assert access.revoke_refresh_token(refresh_token)

    def test_revoke_refresh_token_unexistent_successfully(self):
        assert access.revoke_refresh_token("refresh_token")

    def test_revoke_refresh_token_and_use_old_refresh_token_fails(self):
        refresh_token = generate_refresh_token_for_test()
        assert access.revoke_refresh_token(refresh_token)
        with pytest.raises(UnauthorizedException):
            access.get_tokens(refresh_token=refresh_token)

    def test_revoke_refresh_token_invalid_and_use_valid_refresh_token_successfully(
        self,
    ):
        refresh_token = generate_refresh_token_for_test()
        assert access.revoke_refresh_token("refresh_token")
        user_tokens = access.get_tokens(refresh_token=refresh_token)
        user_tokens = assert_tokens(self, user_tokens)
        assert user_tokens.refresh_token == refresh_token


class TestScribeSelfManagedSigner:
    private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAwhvqCC+37A+UXgcvDl+7nbVjDI3QErdZBkI1VypVBMkKKWHM\nNLMdHk0bIKL+1aDYTRRsCKBy9ZmSSX1pwQlO/3+gRs/MWG27gdRNtf57uLk1+lQI\n6hBDozuyBR0YayQDIx6VsmpBn3Y8LS13p4pTBvirlsdX+jXrbOEaQphn0OdQo0WD\noOwwsPCNCKoIMbUOtUCowvjesFXlWkwG1zeMzlD1aDDS478PDZdckPjT96ICzqe4\nO1Ok6fRGnor2UTmuPy0f1tI0F7Ol5DHAD6pZbkhB70aTBuWDGLDR0iLenzyQecmD\n4aU19r1XC9AHsVbQzxHrP8FveZGlV/nJOBJwFwIDAQABAoIBAFCVFBA39yvJv/dV\nFiTqe1HahnckvFe4w/2EKO65xTfKWiyZzBOotBLrQbLH1/FJ5+H/82WVboQlMATQ\nSsH3olMRYbFj/NpNG8WnJGfEcQpb4Vu93UGGZP3z/1B+Jq/78E15Gf5KfFm91PeQ\nY5crJpLDU0CyGwTls4ms3aD98kNXuxhCGVbje5lCARizNKfm/+2qsnTYfKnAzN+n\nnm0WCjcHmvGYO8kGHWbFWMWvIlkoZ5YubSX2raNeg+YdMJUHz2ej1ocfW0A8/tmL\nwtFoBSuBe1Z2ykhX4t6mRHp0airhyc+MO0bIlW61vU/cPGPos16PoS7/V08S7ZED\nX64rkyECgYEA4iqeJZqny/PjOcYRuVOHBU9nEbsr2VJIf34/I9hta/mRq8hPxOdD\n/7ES/ZTZynTMnOdKht19Fi73Sf28NYE83y5WjGJV/JNj5uq2mLR7t2R0ZV8uK8tU\n4RR6b2bHBbhVLXZ9gqWtu9bWtsxWOkG1bs0iONgD3k5oZCXp+IWuklECgYEA27bA\n7UW+iBeB/2z4x1p/0wY+whBOtIUiZy6YCAOv/HtqppsUJM+W9GeaiMpPHlwDUWxr\n4xr6GbJSHrspkMtkX5bL9e7+9zBguqG5SiQVIzuues9Jio3ZHG1N2aNrr87+wMiB\nxX6Cyi0x1asmsmIBO7MdP/tSNB2ebr8qM6/6mecCgYBA82ZJfFm1+8uEuvo6E9/R\nyZTbBbq5BaVmX9Y4MB50hM6t26/050mi87J1err1Jofgg5fmlVMn/MLtz92uK/hU\nS9V1KYRyLc3h8gQQZLym1UWMG0KCNzmgDiZ/Oa/sV5y2mrG+xF/ZcwBkrNgSkO5O\n7MBoPLkXrcLTCARiZ9nTkQKBgQCsaBGnnkzOObQWnIny1L7s9j+UxHseCEJguR0v\nXMVh1+5uYc5CvGp1yj5nDGldJ1KrN+rIwMh0FYt+9dq99fwDTi8qAqoridi9Wl4t\nIXc8uH5HfBT3FivBtLucBjJgOIuK90ttj8JNp30tbynkXCcfk4NmS23L21oRCQyy\nlmqNDQKBgQDRvzEB26isJBr7/fwS0QbuIlgzEZ9T3ZkrGTFQNfUJZWcUllYI0ptv\ny7ShHOqyvjsC3LPrKGyEjeufaM5J8EFrqwtx6UB/tkGJ2bmd1YwOWFHvfHgHCZLP\n34ZNURCvxRV9ZojS1zmDRBJrSo7+/K0t28hXbiaTOjJA18XAyyWmGg==\n-----END RSA PRIVATE KEY-----\n"
    public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwhvqCC+37A+UXgcvDl+7\nnbVjDI3QErdZBkI1VypVBMkKKWHMNLMdHk0bIKL+1aDYTRRsCKBy9ZmSSX1pwQlO\n/3+gRs/MWG27gdRNtf57uLk1+lQI6hBDozuyBR0YayQDIx6VsmpBn3Y8LS13p4pT\nBvirlsdX+jXrbOEaQphn0OdQo0WDoOwwsPCNCKoIMbUOtUCowvjesFXlWkwG1zeM\nzlD1aDDS478PDZdckPjT96ICzqe4O1Ok6fRGnor2UTmuPy0f1tI0F7Ol5DHAD6pZ\nbkhB70aTBuWDGLDR0iLenzyQecmD4aU19r1XC9AHsVbQzxHrP8FveZGlV/nJOBJw\nFwIDAQAB\n-----END PUBLIC KEY-----\n"

    def test_signer_successfully(self):
        signer = SelfManagedSigner(self.private_key, "issuer", "sub")
        exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            seconds=60
        )
        token = signer.sign(["read", "write"], int(exp.timestamp()))
        assert isinstance(token, str)
        claims = jwt.decode(
            token, self.public_key, algorithms=["RS256"], options={"verify_aud": False}
        )
        assert claims["sub"] == "sub"
        assert claims["iss"] == "issuer"
        assert claims["scope"] == "read write"
        assert claims["aud"] == "https://apis.scribelabs.ai"


class TestDecodeSelfSignedToken:
    expired_signed_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJzdWIiOiJzdWIiLCJhdWQiOiJodHRwczovL2FwaXMuc2NyaWJlbGFicy5haSIsInNjb3BlIjoicmVhZCB3cml0ZSIsImV4cCI6MTc0MTgxNzgxMn0.LLzyN0ggqfmurfHs-fZeiCNemJgIOhlIWcxj97vYQjv6CN_deRcL6lTnrQh7G0_y2XpPkRlZu_aW6RufHi7GMVY6DvJHLuiPdKY6TnsMb7gUY9FFT5y3WawYjwQXot0x6DoeHC12D-LbLiZTPmFworEq-jDJJeM2ScdOzm03QTuARob7T7IcaE1aSPuox1TvxnaGcZzrZZ3z_odF2PQYKVxvgof2Yu3o67oXQ_FCPbdfbHn-RlAlmbl7MvkAit5-v-8BHBYSzznB1VZw3Y30n27eGBdZf4PsgNnHSpJzQmvBW59DM8CW_zdQz-oj5zcDMIV2Lw16qhTQZsuN3u1lcg"

    def test_decode_token_successfully(self):
        token = generate_signed_token()
        claims = decode_self_signed_jwt(token, TestScribeSelfManagedSigner.public_key)
        assert claims["sub"] == "sub"
        assert claims["iss"] == "issuer"
        assert claims["scope"] == "read write"
        assert claims["aud"] == "https://apis.scribelabs.ai"

    def test_decode_token_expired(self):
        with pytest.raises(jwt.ExpiredSignatureError):
            decode_self_signed_jwt(
                self.expired_signed_token, TestScribeSelfManagedSigner.public_key
            )

    def test_decode_token_wrong_public_key(self):
        with pytest.raises(jwt.InvalidKeyError):
            decode_self_signed_jwt(self.expired_signed_token, "key")


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


def generate_signed_token():
    signer = SelfManagedSigner(TestScribeSelfManagedSigner.private_key, "issuer", "sub")
    exp = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 60
    token = signer.sign(["read", "write"], exp)
    return token
