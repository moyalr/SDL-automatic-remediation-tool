import os
from aia_auth import auth
import base64
import httpx
import math
import time
import uuid


"""Authentication helpers for calling Dell internal services.

This module provides:
- A simple token provider that supports SSO or OAuth client-credentials.
- An httpx.Auth implementation that refreshes OAuth tokens on the client side.

Environment variables expected:
- USE_SSO: "true"/"false"
- CLIENT_ID, CLIENT_SECRET: required when USE_SSO is false
"""

class AuthenticationProvider:
    """Generates Authorization values for Dell gateway requests.

    The provider supports two modes:
    - SSO: Uses `aia_auth.auth.sso()` and returns a Bearer token.
    - Client Credentials: Uses `aia_auth.auth.client_credentials()`.
    """

    def __init__(self):
        """
        Initialize provider configuration from environment variables.

        Reads:
        - `USE_SSO` ("true"/"false")
        - `CLIENT_ID` / `CLIENT_SECRET` (OAuth client-credentials)
        """
        self.use_sso = (os.getenv("USE_SSO") or "").lower() == "true"
        # Below properties are applicable to OAUTH only
        self.client_id = os.getenv("CLIENT_ID")
        self.client_secret = os.getenv("CLIENT_SECRET")

    def generate_auth_token(self) -> str:
        """
        Generate an access token based on the configured authentication method.

        The method defaults to `client_credentials` if `use_sso` is not explicitly
        set to "true".

        Returns:
            str: Access token string (without the "Bearer " prefix).
        """
        if self.use_sso:
            return self._sso()
                
        return self._get_bearer_token()
    
    def get_basic_credentials(self) -> str:
        """
        Return a Basic auth payload for server-side token refresh scenarios.

        This returns the base64-encoded `client_id:client_secret` string.

        Returns:
            str: Base64 encoded client credentials in the form "client_id:client_secret".
        """
        self._validate_client_credentials()
        return base64.b64encode(f'{self.client_id}:{self.client_secret}'.encode()).decode()

    def _get_bearer_token(self) -> str:
        """
        Generates an authentication token using the Client Credentials flow.

        This method assumes that `client_id` and `client_secret` are globally
        available or passed in a different context. It first validates these
        credentials before requesting a token.

        Returns:
            str: The authentication token.
        """
        self._validate_client_credentials()
        return auth.client_credentials(self.client_id, self.client_secret).token

    def _sso(self) -> str:
        """
        Generates an authentication token using the Single Sign-On (SSO) flow.

        This method leverages the `auth.sso()` function to obtain a token,
        which typically involves a user interaction or a pre-configured
        session.

        Returns:
            str: The authentication token.
        """
        access_token = auth.sso()
        return access_token.token    
    
    def _validate_client_credentials(self):
        """
        Validate that `CLIENT_ID` and `CLIENT_SECRET` are populated.

        Returns:
            None: Raises an exception if invalid.
        """
        if self.client_id == 'Insert_your_client_id_here' or self.client_id is None or self.client_secret == 'Insert_your_client_secret_here' or self.client_secret is None:
            print("*** Please set the CLIENT_ID & CLIENT_SECRET in environment variables or set Use_SSO to true. ***")
            raise Exception("Invalid client credentials")

class AuthenticationProviderWithClientSideTokenRefresh(httpx.Auth):
    """httpx.Auth that injects a Bearer token and refreshes it when expired.

    Intended for OAuth client-credentials flows where the client is responsible
    for refreshing the token.
    """

    def __init__(self):
        """
        Initialize the auth handler and read OAuth client credentials.

        Reads `CLIENT_ID` and `CLIENT_SECRET` from environment variables.
        """
        # Below properties are applicableto OAUTH only
        self.client_id = os.getenv("CLIENT_ID")
        self.client_secret = os.getenv("CLIENT_SECRET")
        self.last_refreshed = math.floor(time.time())
        self.valid_until = math.floor(time.time()) - 1
        self._validate_client_credentials()
    
    def auth_flow(self, request):
        """
        httpx auth flow: add correlation id and Authorization header.

        Parameters:
            request: httpx.Request

        Returns:
            Iterator of httpx.Request
        """
        if "x-correlation-id" not in request.headers:
            request.headers["x-correlation-id"] = str(uuid.uuid4())
        request.headers["Authorization"] = f"Bearer {self.get_bearer_token()}"
        yield request

    def get_bearer_token(self):
        """
        Get a cached bearer token, refreshing it if expired.
        
        Returns:
            str: The generated or existing bearer token.
        """
        if self._is_expired():
            print("Generating new token...\n")
            self.last_refreshed = math.floor(time.time())
            _resp = auth.client_credentials(self.client_id, self.client_secret)
            self.token = _resp.token
            self.expires_in = _resp.expires_in
            self.valid_until = self.last_refreshed + self.expires_in
        else:
            print("Token not expired, using cached token...\n")
        return self.token

    def _validate_client_credentials(self):
        """
        Validate that `CLIENT_ID` and `CLIENT_SECRET` are populated.

        Returns:
            None: Raises an exception if invalid.
        """
        if self.client_id == 'Insert_your_client_id_here' or self.client_id is None or self.client_secret == 'Insert_your_client_secret_here' or self.client_secret is None:
            print("*** Please set the CLIENT_ID & CLIENT_SECRET in environment variables or set Use_SSO to true. ***")
            raise Exception("Invalid client credentials")

    def _is_expired(self):
        """
        Check whether the cached token is expired.

        Returns:
            bool: True if the token has expired, False otherwise.
        """
        return time.time() >= self.valid_until