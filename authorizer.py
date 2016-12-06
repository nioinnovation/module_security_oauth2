import re
from fnmatch import fnmatch

from nio.modules.security.authorizer import Unauthorized
from nio.modules.security.user import User
from nio.modules.security.task import SecureTask


class Authorizer(object):

    _permissions = {}

    @classmethod
    def configure(cls, context):
        cls._permissions = context.permissions

    @classmethod
    def authorize(cls, user, task):
        if not isinstance(user, User) or not isinstance(task, SecureTask):
            raise Unauthorized()

        for perm_def in cls._get_permissions_for_user(user.name):
            # See if the permission we are checking is in the user's
            # permission set
            if cls._permission_matches_permission_def(
                    task.resource, task.permission, perm_def):
                # The permission matches, return indicating they are
                # authorized
                return

        # Didn't find the permission, guess we're not authorized
        raise Unauthorized()

    @classmethod
    def _get_permissions_for_user(cls, username):
        """ Function to return a list of permissions for a user """
        if username in cls._permissions:
            return cls._permissions.get(username)
        else:
            # extract domain from potential email address
            domain = re.search('@.+', username)
            if domain:
                # extract domain + remove @
                domain = re.search('@.+', username).group()[1:]
                return cls._permissions.get(domain, [])
            else:
                return []

    @classmethod
    def _permission_matches_permission_def(cls, resource, permission, perm_def):
        """ Checks that a permission matches a permission definition

        The permission definition is the one that should come from the config
        and can have certain rules (like * wildcards)

        Example:
            >> _permission_matches_permission_def("a.b", "a.*") == True
            >> _permission_matches_permission_def("a.b", "a.b") == True
            >> _permission_matches_permission_def("a.b", "a") == False
        """
        # Going to hack this by using fnmatch which matches filenames
        # https://docs.python.org/3.5/library/fnmatch.html
        return fnmatch("{}.{}".format(resource, permission), perm_def)
