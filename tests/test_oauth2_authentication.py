from unittest.mock import MagicMock, patch

from nio.modules.context import ModuleContext
from nio.modules.security import Unauthorized
from nio.testing.test_case import NIOTestCase

from ..authenticator import Authenticator, InvalidToken
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
        """ Asserts that when 'verify' returns None
        a 'Guest' (default user) is returned """
        with patch.object(Authenticator, 'verify', return_value=None):
            request = MagicMock()
            args = {"request": request}
            user = Authenticator.authenticate(**args)
            # Returns default user ?
            self.assertIsNotNone(user)
            # Returns user is guest ?
            self.assertEqual("Guest", user.name)
            # verify called
            Authenticator.verify.assert_called_once_with(request)

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

        token_jwt = {"email": "myemail@server.com"}
        # Check Bearer prefix
        with patch.object(Authenticator, '_request_token'):
            with patch.object(Authenticator, '_verify_access_token',
                              return_value=token_jwt):
                request = MagicMock()
                request.get_header = MagicMock(return_value="Bearer 12345")
                user = Authenticator.authenticate(request=request)
                Authenticator.\
                    _verify_access_token.assert_called_once_with("12345")
                Authenticator._request_token.assert_called_once()
                self.assertEqual('myemail@server.com', user.name)

        # Check OAuth prefix
        with patch.object(Authenticator, '_request_token'):
            with patch.object(Authenticator, '_verify_access_token',
                              return_value=token_jwt):
                request = MagicMock()
                request.get_header = MagicMock(return_value="OAuth 45678")
                user = Authenticator.authenticate(request=request)
                Authenticator.\
                    _verify_access_token.assert_called_once_with("45678")
                Authenticator._request_token.assert_called_once()
                self.assertEqual('myemail@server.com', user.name)

    def test_oAuthenticator2_invalid_prefix(self):
        """ Asserts that when header's prefix is not Bearer nor OAuth,
        a Guest is returned """

        # Check Bearer prefix
        request = MagicMock()
        request.get_header = MagicMock(return_value="NonBearer 12345")
        user = Authenticator.authenticate(request=request)
        self.assertEqual('Guest', user.name)

    def test_verify_access_token_error(self):
        """ Asserts that when token returns an 'error_description' field,
        Unauthorized is raised """
        token_jwt = {"error_description": "Invalid Scope"}
        with patch.object(Authenticator, '_request_token',
                          return_value=token_jwt):
            request = MagicMock()
            request.get_header = MagicMock(return_value="OAuth 45678")
            with self.assertRaises(Unauthorized):
                Authenticator.authenticate(request=request)

    def test_invalid_token(self):
        """ Asserts that an InvalidToken exception raised by 'verify'
        is translated to an Unauthorized exception """

        with patch.object(Authenticator, 'verify',
                          side_effect=InvalidToken):
            request = MagicMock()
            with self.assertRaises(Unauthorized):
                Authenticator.authenticate(request=request)

    def test_request_access_failure(self):
        """ Asserts that an exception raised by '_request_token' is translated
        to an Unauthorized exception """

        with patch.object(Authenticator, '_request_token',
                          side_effect=RuntimeError):
            request = MagicMock()
            request.get_header = MagicMock(return_value="OAuth 45678")
            with self.assertRaises(Unauthorized):
                Authenticator.authenticate(request=request)
