import unittest
from scribeauth import ScribeAuth, Tokens
from scribeauth.scribeauth import UnauthorizedException
import os
from dotenv import load_dotenv

load_dotenv()

client_id: str = os.environ.get("CLIENT_ID")
client_id2: str = os.environ.get("CLIENT_ID2")
username: str = os.environ.get("USER")
password: str = os.environ.get("PASSWORD")
password2: str = os.environ.get("PASSWORD2")
user_pool_id: str = os.environ.get("USER_POOL_ID")
federated_pool_id: str = os.environ.get("FEDERATED_POOL_ID")
expected_federated_id: str = os.environ.get("FEDERATED_ID")
access = ScribeAuth(client_id)
pool_access = ScribeAuth({'client_id': client_id2, 'user_pool_id': user_pool_id, 'identity_pool_id': federated_pool_id})

class TestScribeAuthGetTokens(unittest.TestCase):

    def test_get_tokens_username_password_successfully(self):
        user_tokens: Tokens = access.get_tokens(username=username, password=password)
        assert_tokens(self, user_tokens)

    def test_get_tokens_wrong_username_fails(self):
        with self.assertRaises(UnauthorizedException):
            self.assertRaises(access.get_tokens(username='username', password=password))

    def test_get_tokens_wrong_password_fails(self):
        with self.assertRaises(UnauthorizedException):
            self.assertRaises(access.get_tokens(username=username, password='password'))

    def test_get_tokens_empty_username_fails(self):
        with self.assertRaises(UnauthorizedException):
            self.assertRaises(access.get_tokens(password=password))
            
    def test_get_tokens_empty_password_fails(self):            
        with self.assertRaises(UnauthorizedException):
            self.assertRaises(access.get_tokens(username=username))

    def test_get_tokens_empty_username_and_password_fails(self):
        with self.assertRaises(UnauthorizedException):
            self.assertRaises(access.get_tokens())

    def test_get_tokens_refresh_token_successfully(self):
        refresh_token = generate_refresh_token_for_test()
        user_tokens: Tokens = access.get_tokens(refresh_token=refresh_token)
        assert_tokens(self, user_tokens)
        self.assertEqual(refresh_token, user_tokens.get('refresh_token'))

    def test_get_tokens_refresh_token_fails(self):
        with self.assertRaises(UnauthorizedException):
            self.assertRaises(access.get_tokens(refresh_token='refresh_token'))

    def test_get_tokens_refresh_token_multiple_params_successfully(self):
        refresh_token = generate_refresh_token_for_test()
        user_tokens: Tokens = access.get_tokens(**{'refresh_token': refresh_token})
        assert_tokens(self, user_tokens)
        self.assertEqual(refresh_token, user_tokens.get('refresh_token'))

    def test_get_tokens_refresh_token_multiple_params_fails(self):
        with self.assertRaises(UnauthorizedException):
            self.assertRaises(access.get_tokens(**{'refresh_token': 'refresh_token'}))


class TestScribeAuthRevokeRefreshTokens(unittest.TestCase):

    def test_revoke_refresh_token_successfully(self):
        refresh_token = generate_refresh_token_for_test()
        self.assertTrue(access.revoke_refresh_token(refresh_token))
        
    def test_revoke_refresh_token_unexistent_successfully(self):
        self.assertTrue(access.revoke_refresh_token('refresh_token'))

    def test_revoke_refresh_token_and_use_old_refresh_token_fails(self):
        refresh_token = generate_refresh_token_for_test()
        self.assertTrue(access.revoke_refresh_token(refresh_token))
        with self.assertRaises(UnauthorizedException):
            self.assertRaises(access.get_tokens(refresh_token=refresh_token))

    def test_revoke_refresh_token_invalid_and_use_valid_refresh_token_successfully(self):
        refresh_token = generate_refresh_token_for_test()
        self.assertTrue(access.revoke_refresh_token('refresh_token'))
        user_tokens: Tokens = access.get_tokens(refresh_token=refresh_token)
        assert_tokens(self, user_tokens)
        self.assertEqual(refresh_token, user_tokens.get('refresh_token'))


class TestScribeAuthFederatedCredentials(unittest.TestCase):

    def test_get_federated_id_successfully(self):
        user_tokens: Tokens = pool_access.get_tokens(username=username, password=password2)
        id_token = user_tokens.get('id_token')
        federated_id = pool_access.get_federated_id(id_token)
        self.assertEqual(expected_federated_id, federated_id)
        
    def test_get_federated_id_fails(self):
        with self.assertRaises(UnauthorizedException):
            self.assertRaises(pool_access.get_federated_id('id_token'))

    def test_get_federated_credentials_successfully(self):
        user_tokens: Tokens = pool_access.get_tokens(username=username, password=password2)
        id_token = user_tokens.get('id_token')
        federated_credentials = pool_access.get_federated_credentials(expected_federated_id, id_token)
        self.assertTrue(federated_credentials.get('AccessKeyId'))
        self.assertTrue(federated_credentials.get('SecretKey'))
        self.assertTrue(federated_credentials.get('SessionToken'))
        self.assertTrue(federated_credentials.get('Expiration'))

    def test_get_federated_credentials_fails(self):
        user_tokens: Tokens = pool_access.get_tokens(username=username, password=password2)
        id_token = user_tokens.get('id_token')
        with self.assertRaises(Exception):
            self.assertRaises(pool_access.get_federated_credentials('id', id_token))

def generate_refresh_token_for_test():
    return access.get_tokens(username=username, password=password).get('refresh_token')

def assert_tokens(self, user_tokens):
    self.assertIsNotNone(user_tokens.get('refresh_token'))
    self.assertIsNotNone(user_tokens.get('access_token'))
    self.assertIsNotNone(user_tokens.get('id_token'))
    self.assertNotEqual(user_tokens.get('refresh_token'), user_tokens.get('access_token'))
    self.assertNotEqual(user_tokens.get('refresh_token'), user_tokens.get('id_token'))
    self.assertNotEqual(user_tokens.get('id_token'), user_tokens.get('access_token'))
