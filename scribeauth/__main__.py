import argparse

from scribeauth import ScribeAuth
from scribeauth.scribeauth import Challenge

if __name__ == "__main__":
    parser = argparse.ArgumentParser("scribeauth")
    parser.add_argument("--client_id", help="Client ID provided by Scribe", type=str)
    parser.add_argument(
        "--user_pool_id", help="User pool ID provided by Scribe", type=str
    )
    parser.add_argument("--username", help="Username", type=str)
    parser.add_argument("--password", help="Password", type=str)
    parser.add_argument("--refresh_token", help="Refresh Token", type=str)
    args = parser.parse_args()
    auth = ScribeAuth(client_id=args.client_id, user_pool_id=args.user_pool_id)
    if args.refresh_token:
        tokens = auth.get_tokens(refresh_token=args.refresh_token)
    else:
        tokens = auth.get_tokens(username=args.username, password=args.password)
        if (
            isinstance(tokens, Challenge)
            and tokens.challenge_name == "SOFTWARE_TOKEN_MFA"
        ):
            code = input("Enter MFA code: ")
            tokens = auth.respond_to_auth_challenge_mfa(
                username=args.username, session=tokens.session, code=code
            )
    print(tokens)
