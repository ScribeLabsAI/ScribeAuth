from typing import List

import boto3
import botocore
import botocore.session
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.config import Config
from botocore.exceptions import NoAuthTokenError
from typing_extensions import NotRequired, TypedDict, Unpack


class Tokens(TypedDict):
    refresh_token: str
    access_token: str
    id_token: str


class Challenge(TypedDict):
    challenge_name: str
    session: str


class RefreshToken(TypedDict):
    refresh_token: str


class UsernamePassword(TypedDict):
    username: str
    password: str


class Credentials(TypedDict):
    AccessKeyId: str
    SecretKey: str
    SessionToken: str
    Expiration: str


class PoolConfiguration(TypedDict):
    client_id: str
    user_pool_id: str
    identity_pool_id: NotRequired[str | None]


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


def is_complete_credentials(cred: Credentials) -> bool:
    return "AccessKeyId" in cred and "SecretKey" in cred and "SessionToken" in cred


class ScribeAuth:
    def __init__(self, param: PoolConfiguration):
        """Constructs an authorisation client.

        Args
        ----
        PoolConfiguration:

        ---
        client_id -- The client ID of the application provided by Scribe.

        user_pool_id -- The user pool ID provided by Scribe.

        identity_pool_id -- The identity pool ID provided by Scribe. (Optional)
        """
        config = Config(signature_version=botocore.UNSIGNED)
        self.client_unsigned = boto3.client(
            "cognito-idp", config=config, region_name="eu-west-2"
        )
        self.client_signed = boto3.client("cognito-idp", region_name="eu-west-2")
        self.client_id = param.get("client_id")
        self.user_pool_id = param.get("user_pool_id")
        self.identity_pool_id = param.get("identity_pool_id")
        if param.get("identity_pool_id"):
            self.fed_client = boto3.client("cognito-identity", region_name="eu-west-2")

    def change_password(
        self, username: str, password: str, new_password: str
    ) -> bool | Challenge:  # pragma: no cover
        """Changes password for a user.

        Args
        ----
        username -- Username (usually an email address).

        password -- Password associated with this username.

        new_password -- New password for this username.

        Returns
        -------
        bool
        """
        try:
            response_initiate = self.__initiate_auth(username, password)
            challenge_name = response_initiate.get("ChallengeName")
            if challenge_name == None:
                try:
                    auth_result = response_initiate.get("AuthenticationResult")
                    access_token = auth_result.get("AccessToken")
                    self.__change_password_cognito(password, new_password, access_token)
                    return True
                except Exception as err:
                    raise err
            else:
                if not hasattr(self, "client_id"):
                    raise MissingIdException("Missing client ID")
                session = response_initiate.get("Session")
                challenge_parameters = response_initiate.get("ChallengeParameters")
                required_attributes = challenge_parameters.get("requiredAttributes")
                try:
                    if challenge_name == "NEW_PASSWORD_REQUIRED":
                        user_id_SRP = challenge_parameters.get("USER_ID_FOR_SRP")
                        self.__respond_to_password_challenge(
                            username,
                            new_password,
                            session,
                            user_id_SRP,
                            required_attributes,
                        )
                        return True
                    else:
                        return response_initiate
                except Exception:
                    raise Exception("InternalServerError: try again later")
        except self.client_signed.exceptions.MissingIdException:
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

        Args
        ----
        username -- Username (usually an email address).

        password -- Password associated with this username.

        confirmation_code -- Confirmation code sent to the user's email.

        Returns
        -------
        bool
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

    def get_tokens(
        self, **param: Unpack[UsernamePassword] | Unpack[RefreshToken]
    ) -> Tokens | Challenge:
        """A user gets their tokens (refresh_token, access_token and id_token).

        Args
        ----
        username -- Username (usually an email address).

        password -- Password associated with this username.

        Or

        refresh_token -- Refresh token to use.

        Returns
        -------
        Tokens -- Dictionary {"refresh_token": "str", "access_token": "str", "id_token": "str"}
        """
        refresh_token = param.get("refresh_token")
        username = param.get("username")
        password = param.get("password")
        if refresh_token == None:
            if isinstance(username, str) and isinstance(password, str):
                return self.__get_tokens_with_pair(username, password)
        elif isinstance(refresh_token, str):
            return self.__get_tokens_with_refresh(refresh_token)
        raise UnauthorizedException(
            "Username and/or Password are missing or refresh_token is missing"
        )

    def respond_to_auth_challenge_mfa(
        self, username: str, session: str, code: str
    ) -> Tokens:
        """Respond to an MFA auth challenge with a code generated from an auth app (e.g. Authy).

        Args
        ----
        username -- Username (usually an email address).

        session -- Challenge session.

        code -- Code generated from an auth app.

        Returns
        -------
        Tokens -- Dictionary {"refresh_token": "str", "access_token": "str", "id_token": "str"}
        """
        try:
            response = self.__respond_to_mfa_challenge(username, session, code)
            result = response.get("AuthenticationResult")
            return {
                "refresh_token": result.get("RefreshToken"),
                "access_token": result.get("AccessToken"),
                "id_token": result.get("IdToken"),
            }
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

        Args
        ----
        refresh_token -- Refresh token to be revoked.

        Returns
        -------
        bool
        """
        response = self.__revoke_token(refresh_token)
        status_code = response.get("ResponseMetadata").get("HTTPStatusCode")
        if status_code == 200:
            return True
        if status_code == 400:  # pragma: no cover
            raise TooManyRequestsException("Too many requests. Try again later")
        else:  # pragma: no cover
            raise Exception("InternalServerError: Try again later")

    def get_federated_id(self, id_token: str) -> str:
        """A user gets their federated id.

        Args
        ----
        id_token -- Id token to use.

        Returns
        -------
        str
        """
        if not hasattr(self, "user_pool_id"):
            raise MissingIdException("Missing user pool ID")
        if not hasattr(self, "fed_client"):
            raise MissingIdException(
                "Federated pool ID is not provided. Create a new ScribeAuth object using identity_pool_id"
            )
        try:
            response = self.fed_client.get_id(
                IdentityPoolId=self.identity_pool_id,
                Logins={
                    f"cognito-idp.eu-west-2.amazonaws.com/{self.user_pool_id}": id_token
                },
            )
            if not response.get("IdentityId"):
                raise UnknownException("Could not retrieve federated id")
            return response.get("IdentityId")
        except self.fed_client.exceptions.NotAuthorizedException:
            raise UnauthorizedException("Could not retrieve federated id")
        except self.fed_client.exceptions.TooManyRequestsException:
            raise TooManyRequestsException("Too many requests. Try again later")
        except Exception as err:
            raise err

    def get_federated_credentials(self, id: str, id_token: str) -> Credentials:
        """A user gets their federated credentials (AccessKeyId, SecretKey and SessionToken).

        Args
        ----
        id -- Federated id.

        id_token -- Id token to use.

        Returns
        -------
        Credentials -- Dictionary {"AccessKeyId": "str", "SecretKey": "str", "SessionToken": "str", "Expiration": "str"}
        """
        if not hasattr(self, "user_pool_id"):
            raise MissingIdException("Missing user pool ID")
        if not hasattr(self, "fed_client"):
            raise MissingIdException(
                "Federated pool ID is not provided. Create a new ScribeAuth object using identity_pool_id"
            )
        try:
            response = self.fed_client.get_credentials_for_identity(
                IdentityId=id,
                Logins={
                    f"cognito-idp.eu-west-2.amazonaws.com/{self.user_pool_id}": id_token
                },
            )
            if not is_complete_credentials(response["Credentials"]):
                raise UnknownException("Could not retrieve federated credentials")
            return response["Credentials"]
        except self.fed_client.exceptions.NotAuthorizedException:
            raise UnauthorizedException("Could not retrieve federated credentials")
        except self.fed_client.exceptions.TooManyRequestsException:
            raise TooManyRequestsException("Too many requests. Try again later")
        except self.fed_client.exceptions.ResourceNotFoundException:
            raise ResourceNotFoundException("Invalid federated_id")
        except Exception as err:
            raise err

    def get_signature_for_request(self, request: AWSRequest, credentials: Credentials):
        """A user gets a signature for a request.

        Args
        ----

        request -- Request to send.

        credentials -- Credentials for the signature creation.

        Returns
        -------
        Headers -- Headers containing the signature for the request.
        """
        try:
            session = botocore.session.Session()
            session.set_credentials(
                access_key=credentials["AccessKeyId"],
                secret_key=credentials["SecretKey"],
                token=credentials["SessionToken"],
            )
            signer = SigV4Auth(
                credentials=session.get_credentials(),
                service_name="execute-api",
                region_name="eu-west-2",
            )
            request.context["payload_signing_enabled"] = False
            signer.add_auth(request=request)
            prepped = request.prepare()
            return prepped.headers
        except Exception as err:
            raise err

    def __get_tokens_with_pair(
        self, username: str, password: str
    ) -> Tokens | Challenge:
        auth_result = "AuthenticationResult"
        if username != None and password != None:
            try:
                response = self.__initiate_auth(username, password)
                result = response.get(auth_result)
                if "ChallengeName" in response:
                    return {
                        "challenge_name": response.get("ChallengeName"),
                        "session": response.get("Session"),
                    }
                else:
                    return {
                        "refresh_token": result.get("RefreshToken"),
                        "access_token": result.get("AccessToken"),
                        "id_token": result.get("IdToken"),
                    }
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
            return {
                "refresh_token": refresh_token,
                "access_token": result.get("AccessToken"),
                "id_token": result.get("IdToken"),
            }
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
        self,
        username: str,
        new_password: str,
        session: str,
        user_id_SRP: str,
        required_attributes: List[str],
    ):  # pragma: no cover
        response = self.client_signed.respond_to_auth_challenge(
            ClientId=self.client_id,
            ChallengeName="NEW_PASSWORD_REQUIRED",
            Session=session,
            ChallengeResponses={
                "USER_ID_FOR_SRP": user_id_SRP,
                "requiredAttributes": required_attributes,
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
