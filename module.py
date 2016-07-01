from nio.modules.context import ModuleContext
from nio.modules.settings import Settings
from nio.modules.security.module import SecurityModule
from nio import discoverable

from .authenticator import Authenticator
from .authorizer import Authorizer


@discoverable
class OAuth2SecurityModule(SecurityModule):

    def initialize(self, context):
        super().initialize(context)
        self.proxy_authenticator_class(Authenticator)
        self.proxy_authorizer_class(Authorizer)

        Authenticator.configure(context)
        Authorizer.configure(context)

    def _prepare_common_context(self):
        context = ModuleContext()

        context.client_id = \
            Settings.get("security", "client_id",
                         fallback="407408718192.apps.googleusercontent.com")
        context.validate_uri = \
            Settings.get("security", "validate_uri",
                         fallback="https://www.googleapis.com/oauth2/v2/"
                                  "tokeninfo?access_token=%s")

        context.permissions = \
            Settings.getdict('security',
                             'permissions', fallback="etc/permissions.json")

        return context

    def prepare_core_context(self):
        return self._prepare_common_context()

    def prepare_service_context(self, service_context=None):
        return self._prepare_common_context()
