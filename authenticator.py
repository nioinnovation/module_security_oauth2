"""

  OAuth 2 Authenticator based on oauth2client Google client library
  ported to python 3

  see: https://github.com/enorvelle/GoogleApiPython3x

"""
import json
import requests
from nio.util.logging import get_nio_logger
from nio.modules.security import Unauthorized
from nio.modules.security.user import User


class InvalidToken(Exception):

    """ Invalid Token received """
    pass


class Authenticator(object):

    """ OAuth2 Authenticator

    Relies on receiving an OAuth2 token in the request.
    This token can be a token created using OpenId Connect authentication

    At this moment we relaying on email scope being present when a token is
    requested from the OP
    We are using this email as user name for authorization purposes

    """

    client_id = None
    validate_uri = None

    @classmethod
    def configure(cls, context):
        """ Initializes authenticator with context settings

        Args:
            context (ModuleContext): Contains settings to use to configure

        """
        cls.client_id = context.client_id
        cls.validate_uri = context.validate_uri

    @classmethod
    def authenticate(cls, request, **kwargs):
        """ Authenticates a request by validating the access token

        The method used for validating a token is up to the OP.
        In this case we are using a token info uri that returns info related
        to the token. This is the method implemented by Google

        The OAuth2 spec do not really defined the method in which a Resource
        Server (nio) verifies a token with a OP (Google) although a work is
        in progress to define this interaction

        We are using email as user name. for the OP to create a token with
        email info the email scope has to be defined when requesting a token
        Also, we recommend using a openid scope as well

        Args:
            request: web request

        Raises:
            Unauthorized: Failure to authenticate
        """
        try:
            token_jwt = cls.verify(request)
            if token_jwt is not None:
                get_nio_logger("Oauth2.Authenticator").debug(
                    "Access token issued for accessing : {0}".
                    format(token_jwt.get('scope')))
                email = token_jwt.get('email', None)
                # We are looking for a token created with email scope
                if email is None:
                    raise InvalidToken()
            else:
                return User()
        except InvalidToken:
            raise Unauthorized()

        return User(name=email)

    @classmethod
    def verify(cls, request):
        """ Obtains request authorization header extracting from it
        a scheme and token and verifies both.

        Args:
            request: web request

        Raises:
            InvalidToken: token does not match expected format or provider
                returned an error
            Unauthorized: Failure to verify token
        """
        auth_header = request.get_header('authorization')
        if auth_header is not None:
            try:
                scheme, token = auth_header.split(' ', 1)
                # make sure scheme is allowed
                if scheme.lower() in ['bearer', 'oauth']:
                    # Verify Access Token
                    return cls._verify_access_token(token)
            except InvalidToken:
                raise
            except Exception:
                get_nio_logger("Oauth2.Authenticator").exception(
                    "Failed to verify token")
                raise Unauthorized()

        return None

    @classmethod
    def _verify_access_token(cls, access_token):
        """ Requests token from provider, if error_description is
        present in provider's result an exception is raised

        Args:
            access_token (str): token to validate with provider

        Raises:
            InvalidToken: provider returned an error_description
        """
        result = cls._request_token(access_token)
        if result.get('error_description') is not None:
            # This is not a valid token.
            get_nio_logger("Oauth2.Authenticator").error(
                "Invalid Id Token : {0}".format(
                    result.get('error_description')))
            raise InvalidToken()
        return result

    @classmethod
    def _request_token(cls, access_token):
        """ Request token info by sending access_token to a validating uri

        Args:
            access_token (str): token to validate with provider

        Returns:
            resulting dictionary obtained from provider's response
        """
        url = (cls.validate_uri % access_token)
        response = requests.request('GET', url)
        return json.loads(response.text)
