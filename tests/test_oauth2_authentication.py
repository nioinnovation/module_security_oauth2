from unittest.mock import MagicMock, patch

from nio.modules.context import ModuleContext
from nio.modules.security import Unauthorized
from nio.modules.web.request import Request
from nio.testing.test_case import NIOTestCase

from ..authenticator import Authenticator
from ..module import OAuth2SecurityModule


class TestOAuthenticator(NIOTestCase):

    def get_test_modules(self):
        return super().get_test_modules() | {'security'}

    def get_module(self, module_name):
        if module_name == 'security':
            return OAuth2SecurityModule()
        else:
            return super().get_module(module_name)

    def get_context(self, module_name, module):
        if module_name == 'security':
            context = ModuleContext()
            context.client_id = "foo_client"
            context.validate_uri = "https://myverifyinguri?access=%s"
            context.permissions = {}
            return context
        else:
            return super().get_context(module_name, module)

    def test_configure(self):
        """ Asserts that context values are assigned as expected """
        self.assertEqual("foo_client", Authenticator.client_id)
        self.assertEqual("https://myverifyinguri?access=%s",
                         Authenticator.validate_uri)

    def test_verify_is_called(self):
        """ Asserts that 'verify' is called and results are as expected """
        oauth_token = {"email": "myemail@server.com"}
        with patch.object(Authenticator, 'verify', return_value=oauth_token):
            request = MagicMock()
            args = {"request": request}
            user = Authenticator.authenticate(**args)
            # verify called
            Authenticator.verify.assert_called_once_with(request)
            # verify user
            self.assertEqual(user.name, oauth_token["email"])

    def test_email_is_used(self):
        """ Asserts that email returned from verify is used as user name """
        with patch.object(Authenticator, 'verify',
                          return_value={"email": "bar@foobar.com"}):
            request = MagicMock()
            args = {"request": request}
            user = Authenticator.authenticate(**args)
            self.assertEqual("bar@foobar.com", user.name)
            Authenticator.verify.assert_called_once_with(request)

    def test_email_is_checked(self):
        """ Asserts that when 'verify' returns data, then data must contain
        the email field """
        with patch.object(Authenticator, 'verify',
                          return_value={"prop": "value"}):
            request = MagicMock()
            args = {"request": request}
            with self.assertRaises(Unauthorized):
                Authenticator.authenticate(**args)

    def test_oAuthenticator2_check_prefixes(self):
        """ Asserts that OAuth and Bearer tokens are valid perfixes as part of
        the Authenticator header """

        oauth_token = {"email": "myemail@server.com"}
        # Check Bearer prefix
        with patch.object(Authenticator, '_verify_access_token',
                          return_value=oauth_token):
            request = MagicMock()
            request.get_header = MagicMock(return_value="Bearer 12345")
            user = Authenticator.authenticate(request=request)
            Authenticator.\
                _verify_access_token.assert_called_once_with("12345")
            self.assertEqual(user.name, oauth_token["email"])

        # Check OAuth prefix
        with patch.object(Authenticator, '_verify_access_token',
                          return_value=oauth_token):
            request = MagicMock()
            request.get_header = MagicMock(return_value="OAuth 45678")
            user = Authenticator.authenticate(request=request)
            Authenticator.\
                _verify_access_token.assert_called_once_with("45678")
            self.assertEqual('myemail@server.com', user.name)

        # patch _validate_token and verify since _verify_access_token's purpose
        # is to add error mgmt. to _validate_token's result
        with patch.object(Authenticator, '_validate_token',
                          return_value=oauth_token):
            request = MagicMock()
            request.get_header = MagicMock(return_value="Bearer 12345")
            user = Authenticator.authenticate(request=request)
            Authenticator. \
                _validate_token.assert_called_once_with("12345")
            self.assertEqual('myemail@server.com', user.name)

    def test_header_missing(self):
        """ Test missing authorization header.

        Raises Unauthorized.
        """
        request = MagicMock(spec=Request)
        request.get_header.return_value = None

        with self.assertRaises(Unauthorized):
            Authenticator.authenticate(request=request)

    def test_oAuthenticator2_invalid_prefix(self):
        """ Asserts that when header's prefix is not Bearer nor OAuth,
        Unauthorized is raised """

        # Check Bearer prefix
        request = MagicMock()
        request.get_header = MagicMock(return_value="NonBearer 12345")
        with self.assertRaises(Unauthorized):
            Authenticator.authenticate(request=request)

    def test_verify_access_token_error(self):
        """ Asserts that when token returns an 'error_description' field,
        Unauthorized is raised """
        oauth_token = {"error_description": "Invalid Scope"}
        with patch.object(Authenticator, '_validate_token',
                          return_value=oauth_token):
            request = MagicMock()
            request.get_header = MagicMock(return_value="OAuth 45678")
            with self.assertRaises(Unauthorized):
                Authenticator.authenticate(request=request)

    def test_invalid_token(self):
        """ Asserts that an InvalidToken exception raised by 'verify'
        is translated to an Unauthorized exception """

        with patch.object(Authenticator, 'verify',
                          side_effect=Unauthorized):
            request = MagicMock()
            with self.assertRaises(Unauthorized):
                Authenticator.authenticate(request=request)

    def test_request_access_failure(self):
        """ Asserts exception from _validate_token propagates to Authenticate
        """

        with patch.object(Authenticator, '_validate_token',
                          side_effect=RuntimeError):
            request = MagicMock()
            request.get_header = MagicMock(return_value="OAuth 45678")
            with self.assertRaises(Unauthorized):
                Authenticator.authenticate(request=request)
