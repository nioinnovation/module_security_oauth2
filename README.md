# nio oauth2 security module

A nio module providing oauth2 security authentication


## Configuration

[security]

api credentials
- client_id=[your_google_client_id]

uri to use to validate tokens
- validate_uri="https://www.googleapis.com/oauth2/v2/tokeninfo?access_token=%s"

user permissions in the system, where each entry is defined as [Username]: [list of permissions] ("Admin": ["*"])
- permissions=etc/permissions.json

## Dependencies

- None
