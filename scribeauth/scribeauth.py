from dataclasses import dataclass
from typing import overload

import boto3
import botocore
import botocore.session
import jwt
from botocore.config import Config
from botocore.exceptions import NoAuthTokenError


@dataclass
class Tokens:
    refresh_token: str
    access_token: str
    id_token: str


@dataclass
class Challenge:
    challenge_name: str
    session: str


class UnauthorizedException(Exception):
    """
    Exception raised when a user cannot perform an action.

    Possible reasons:
    - Username and/or Password are incorrect.
    - Refresh_token is incorrect.
    - MFA code is incorrect or expired.
    """

    pass


class TooManyRequestsException(Exception):
    """
    Exception raised when an action is performed by a user too many times in a short period.

    Actions that could raise this exception:
    - Changing a Password.
    - Revoke Refresh_token.
    """

    pass


class MissingIdException(Exception):
    pass


class ResourceNotFoundException(Exception):
    pass


class UnknownException(Exception):
    pass


class ScribeAuth:
    def __init__(self, client_id: str, user_pool_id: str):
        """Constructs an authorisation client.

        :param client_id: The client ID of the application provided by Scribe.

        :param user_pool_id: The user pool ID provided by Scribe.
        """
        config = Config(signature_version=botocore.UNSIGNED)
        self.client_unsigned = boto3.client(
            "cognito-idp", config=config, region_name="eu-west-2"
        )
        self.client_signed = boto3.client("cognito-idp", region_name="eu-west-2")
        self.client_id = client_id
        self.user_pool_id = user_pool_id

    def change_password(
        self, username: str, password: str, new_password: str
    ) -> bool | Challenge:  # pragma: no cover
        """Changes password for a user.

        :param username: Username (usually an email address).
        :type username: str

        :param password: Password associated with this username.
        :type password: str

        :param new_password: New password for this username.
        :type new_password: str

        :rtype: bool | Challenge
        """
        try:
            response_initiate = self.__initiate_auth(username, password)
            challenge_name = response_initiate.get("ChallengeName")
            if challenge_name == None:
                try:
                    auth_result = response_initiate.get("AuthenticationResult")
                    access_token = auth_result.get("AccessToken", "")
                    self.__change_password_cognito(password, new_password, access_token)
                    return True
                except Exception as err:
                    raise err
            else:
                if not hasattr(self, "client_id"):
                    raise MissingIdException("Missing client ID")
                session = response_initiate.get("Session")
                challenge_parameters = response_initiate.get("ChallengeParameters")
                try:
                    if challenge_name == "NEW_PASSWORD_REQUIRED":
                        user_id_SRP = challenge_parameters.get("USER_ID_FOR_SRP", "")
                        self.__respond_to_password_challenge(
                            username,
                            new_password,
                            session,
                            user_id_SRP,
                        )
                        return True
                    else:
                        return Challenge(
                            challenge_name=response_initiate.get("ChallengeName"),
                            session=response_initiate.get("Session"),
                        )
                except Exception:
                    raise Exception("InternalServerError: try again later")
        except self.client_signed.exceptions.ResourceNotFoundException:
            raise MissingIdException("Missing client ID")
        except self.client_signed.exceptions.TooManyRequestsException:
            raise TooManyRequestsException("Too many requests. Try again later")
        except NoAuthTokenError as err:
            raise UnauthorizedException("Username and/or Password are incorrect.")
        except Exception as err:
            raise err

    def forgot_password(
        self, username: str, password: str, confirmation_code: str
    ) -> bool:  # pragma: no cover
        """Allows a user to enter a confirmation code sent to their email to reset a forgotten password.

        :param username: Username (usually an email address).
        :type username: str

        :param password: Password associated with this username.
        :type password: str

        :param confirmation_code: Confirmation code sent to the user's email.
        :type confirmation_code: str

        :rtype: bool
        """
        try:
            self.client_signed.confirm_forgot_password(
                ClientId=self.client_id,
                Username=username,
                ConfirmationCode=confirmation_code,
                Password=password,
            )
            return True
        except NoAuthTokenError as err:
            raise UnauthorizedException(
                "Username, Password and/or Confirmation_code are incorrect. Could not reset password"
            )
        except Exception as err:
            raise err

    @overload
    def get_tokens(
        self, *, username: str = "", password: str = ""
    ) -> Tokens | Challenge: ...

    @overload
    def get_tokens(self, *, refresh_token: str = "") -> Tokens | Challenge: ...

    def get_tokens(
        self, *, username: str = "", refresh_token: str = "", password: str = ""
    ) -> Tokens | Challenge:
        """A user gets their tokens (refresh_token, access_token and id_token).

        It is possible to pass a username/password pair or a refresh token:

        :param username: Username (usually an email address).
        :type username: str
        :param password: Password (associated with this username).
        :type password: str

        Or

        :param refresh_token: Refresh Token to use.
        :type refresh_token: str

        It returns Tokens or a Challenge:

        :return: Tokens or Challenge
        :rtype: Tokens | Challenge
        """
        if refresh_token:
            return self.__get_tokens_with_refresh(refresh_token)
        elif username and password:
            return self.__get_tokens_with_pair(username, password)
        raise UnauthorizedException(
            "Username and/or Password are missing or refresh_token is missing"
        )

    def respond_to_auth_challenge_mfa(
        self, username: str, session: str, code: str
    ) -> Tokens:
        """Respond to an MFA auth challenge with a code generated from an auth app (e.g. Authy).

        :param username: Username (usually an email address).
        :type username: str

        :param session: Challenge session coming from an authentication attempt.
        :type session: str

        :param code: Code generated from the auth app.
        :type code: str

        :return: Tokens
        :rtype: Tokens
        """
        try:
            response = self.__respond_to_mfa_challenge(username, session, code)
            result = response.get("AuthenticationResult")
            return Tokens(
                refresh_token=result.get("RefreshToken", ""),
                access_token=result.get("AccessToken", ""),
                id_token=result.get("IdToken", ""),
            )
        except self.client_signed.exceptions.CodeMismatchException:
            raise UnauthorizedException("Wrong MFA code")
        except self.client_signed.exceptions.ExpiredCodeException:
            raise UnauthorizedException("Expired MFA code")
        except self.client_signed.exceptions.TooManyRequestsException:
            raise TooManyRequestsException("Too many requests. Try again later")
        except Exception as err:
            raise err

    def revoke_refresh_token(self, refresh_token: str) -> bool:
        """Revokes all of the access tokens generated by the specified refresh token.
        After the token is revoked, the user cannot use the revoked token.

        :param refresh_token: Refresh token to be revoked.
        :type refresh_token: str

        :rtype: bool
        """
        try:
            self.__revoke_token(refresh_token)
            return True
        except self.client_signed.exceptions.TooManyRequestsException:
            raise TooManyRequestsException("Too many requests. Try again later")
        except Exception:
            raise Exception("InternalServerError: Try again later")

    def __get_tokens_with_pair(
        self, username: str, password: str
    ) -> Tokens | Challenge:
        auth_result = "AuthenticationResult"
        if username is not None and password is not None:
            try:
                response = self.__initiate_auth(username, password)
                result = response.get(auth_result)
                if "ChallengeName" in response:
                    return Challenge(
                        challenge_name=response.get("ChallengeName"),
                        session=response.get("Session"),
                    )
                else:
                    refresh_token_resp = result.get("RefreshToken")
                    access_token_resp = result.get("AccessToken")
                    id_token_resp = result.get("IdToken")
                    if (
                        refresh_token_resp is not None
                        and access_token_resp is not None
                        and id_token_resp is not None
                    ):
                        return Tokens(
                            refresh_token=refresh_token_resp,
                            access_token=access_token_resp,
                            id_token=id_token_resp,
                        )
                    else:
                        raise UnknownException("Could not get tokens")
            except:
                raise UnauthorizedException(
                    "Username and/or Password are incorrect. Could not get tokens"
                )
        else:
            raise UnauthorizedException(
                "Username and/or Password are missing. Could not get tokens"
            )

    def __get_tokens_with_refresh(self, refresh_token: str) -> Tokens:
        try:
            auth_result = "AuthenticationResult"
            response = self.client_signed.initiate_auth(
                ClientId=self.client_id,
                AuthFlow="REFRESH_TOKEN_AUTH",
                AuthParameters={"REFRESH_TOKEN": refresh_token},
            )
            result = response.get(auth_result)
            access_token_resp = result.get("AccessToken")
            id_token_resp = result.get("IdToken")
            if access_token_resp is not None and id_token_resp is not None:
                return Tokens(
                    refresh_token=refresh_token,
                    access_token=access_token_resp,
                    id_token=id_token_resp,
                )
            else:
                raise UnknownException("Could not get tokens")
        except:
            raise UnauthorizedException(
                "Refresh_token is incorrect. Could not get tokens"
            )

    def __initiate_auth(self, username: str, password: str):
        response = self.client_signed.initiate_auth(
            ClientId=self.client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
        return response

    def __respond_to_password_challenge(
        self, username: str, new_password: str, session: str, user_id_SRP: str
    ):  # pragma: no cover
        response = self.client_signed.respond_to_auth_challenge(
            ClientId=self.client_id,
            ChallengeName="NEW_PASSWORD_REQUIRED",
            Session=session,
            ChallengeResponses={
                "USER_ID_FOR_SRP": user_id_SRP,
                "USERNAME": username,
                "NEW_PASSWORD": new_password,
            },
        )
        return response

    def __respond_to_mfa_challenge(
        self, username: str, session: str, code: str
    ):  # pragma: no cover
        response = self.client_signed.respond_to_auth_challenge(
            ClientId=self.client_id,
            ChallengeName="SOFTWARE_TOKEN_MFA",
            Session=session,
            ChallengeResponses={"SOFTWARE_TOKEN_MFA_CODE": code, "USERNAME": username},
        )
        return response

    def __change_password_cognito(
        self, password: str, new_password: str, access_token: str
    ):  # pragma: no cover
        response = self.client_signed.change_password(
            PreviousPassword=password,
            ProposedPassword=new_password,
            AccessToken=access_token,
        )
        return response

    def __revoke_token(self, refresh_token: str):
        response = self.client_unsigned.revoke_token(
            Token=refresh_token, ClientId=self.client_id
        )
        return response


@dataclass
class SelfManagedSigner:
    private_key: str
    """
    Private key related to the public key provided to Scribe.
    """
    issuer: str
    """
    Issuer as communicated to Scribe. Usually the company name.
    """
    sub: str
    """
    Account id. Provided by Scribe.
    """

    def sign(self, scopes: list[str], exp: int) -> str:
        """Signs the private key with the private key.

        :param scopes: The scopes to include in the JWT.
        :type scopes: list[str]
        :param exp: The expiration time of the JWT in seconds.
        :type exp: int

        :return: The signed private key.
        :rtype: str
        """

        payload = {
            "iss": self.issuer,
            "sub": self.sub,
            "aud": "https://apis.scribelabs.ai",
            "scope": " ".join(scopes),
            "exp": exp,
        }

        return jwt.encode(
            payload,
            self.private_key,
            algorithm="RS256",
        )


def decode_self_signed_jwt(token: str, public_key: str) -> dict:
    """Decodes a JWT token.

    :param token: The JWT token to decode.
    :type token: str

    :return: The decoded JWT token.
    :rtype: dict
    """

    return jwt.decode(
        token, public_key, algorithms=["RS256"], audience="https://apis.scribelabs.ai"
    )
