from nio.util.logging import get_nio_logger


def handle_backwards_compatibility(permissions):
    for username, user_permissions in permissions.items():
        if user_permissions == ['*']:

            get_nio_logger("Authorizer").warning(
                "User: {} has assigned old style permissions, "
                "please use new dictionary-like convention".format(username))

            permissions[username] = {".*": "rwx"}
