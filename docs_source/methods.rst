Methods
=======

1. Changing password
--------------------

.. code:: python

   from scribeauth import ScribeAuth
   access = ScribeAuth(client_id)
   access.change_password('username', 'password', 'new_password')

2. Recovering an account in case of forgotten password
------------------------------------------------------

.. code:: python

   from scribeauth import ScribeAuth
   access = ScribeAuth(client_id)
   access.forgot_password('username', 'password', 'confirmation_code')

3. Get or generate tokens
-------------------------

With username and password
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

   from scribeauth import ScribeAuth
   access = ScribeAuth(client_id)
   access.get_tokens(username='username', password='password')

With refresh token
~~~~~~~~~~~~~~~~~~

.. code:: python

   from scribeauth import ScribeAuth
   access = ScribeAuth(client_id)
   access.get_tokens(refresh_token='refresh_token')

4. Revoking a refresh token
---------------------------

.. code:: python

   from scribeauth import ScribeAuth
   access = ScribeAuth(client_id)
   access.revoke_refresh_token('refresh_token')

5. Self-signing tokens
---------------------

.. code:: python

   from scribeauth import SelfManagedSigner

    private_key = "" # your private key corresponding to the public key communicated _to_ Scribe
    issuer = "" # your issuer, communicated _to_ Scribe
    sub = "" # Account id, communicated _by_ Scribe
    signer = SelfManagedSigner(private_key, issuer, sub)

    scopes = [...some scopes] # the scopes, mapping communicated _to_ Scribe
    exp = 0 # expiration timestamp
    token = signer.sign(scopes, exp)
