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

        The OAuth2 spec do not really define the method in which a Resource
        Server (nio) verifies a token with a OP (Google) although a work is
        in progress to define this interaction

        We are using email as user name. for the OP to create a token with
        email info the email scope has to be defined when requesting a token
        Also, we recommend using a openid scope as well

        Args:
            request (Request): web request

        Raises:
            Unauthorized: Failure to authenticate
        """

        # obtain request's token
        token_data = cls.verify(request)
        get_nio_logger("Oauth2.Authenticator").debug(
            "Access token issued for accessing : {0}".
            format(token_data.get('scope')))

        # extract email from token
        email = token_data.get('email', None)
        # We are looking for a token created with email scope
        if email is None:
            msg = "email scope data is invalid"
            get_nio_logger("Oauth2.Authenticator").error(msg)
            raise Unauthorized(msg)

        return User(name=email)

    @classmethod
    def verify(cls, request):
        """ Obtains request authorization header extracting from it
        a scheme and token and verifies both.

        Args:
            request: web request

        Raises:
            Unauthorized: Failure to verify token
        """
        # make sure header is provided
        auth_header = request.get_header('authorization')
        if not auth_header:
            msg = "No 'Authorization' header present in request."
            get_nio_logger("Oauth2.Authenticator").error(msg)
            raise Unauthorized(msg)

        # extract scheme and parameters from header
        try:
            scheme, token = auth_header.split(' ', 1)
        except:
            msg = "'Authorization' header is invalid."
            get_nio_logger("Oauth2.Authenticator").error(msg)
            raise Unauthorized(msg)

        # validate scheme
        if scheme.lower() not in ['bearer', 'oauth']:
            msg = "'Authorization' scheme: {} is invalid, " \
                  "expected 'bearer' or 'oauth'.".format(scheme)
            get_nio_logger("Oauth2.Authenticator").error(msg)
            raise Unauthorized(msg)

        # Verify Access Token
        return cls._verify_access_token(token)

    @classmethod
    def _verify_access_token(cls, access_token):
        """ Verifies authorization token with provider

        if error_description is present in provider's result
        an exception is raised

        Args:
            access_token (str): token to validate with provider

        Raises:
            Unauthorized: Failure to verify token

        Returns:
            resulting dictionary obtained from provider's response
        """
        # validate token with provider
        try:
            result = cls._validate_token(access_token)
        except Exception:
            msg = "Failed to verify token"
            get_nio_logger("Oauth2.Authenticator").exception(msg)
            raise Unauthorized(msg)

        # check if an error occurred
        if result.get('error_description') is not None:
            msg = "Invalid Id Token: {0}".\
                format(result.get('error_description'))
            get_nio_logger("Oauth2.Authenticator").error(msg)
            raise Unauthorized(msg)

        # return provider's response as a dictionary
        return result

    @classmethod
    def _validate_token(cls, access_token):
        """ Validate token info by sending access_token to a validating uri

        Args:
            access_token (str): token to validate with provider

        Raises:
            Unauthorized: Failure to verify token

        Returns:
            resulting dictionary obtained from provider's response
        """
        url = (cls.validate_uri % access_token)
        response = requests.request('GET', url)
        if not response.text:
            msg = "Failure to validate access token"
            get_nio_logger("Oauth2.Authenticator").error(msg)
            raise Unauthorized(msg)

        return json.loads(response.text)
