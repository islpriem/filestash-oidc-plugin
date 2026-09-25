# Configuration

The examples use `files.example.com` for Filestash and `auth.example.com` for the identity provider.

## Identity provider

Create a confidential OpenID Connect client with the redirect URI `https://files.example.com/api/session/auth/`.

The ID token has to meet two requirements:

- It is signed with an asymmetric key (RS256, ES256, …).
- It carries a `groups` claim with the list of the user's group names.

The plugin asks for the scopes `openid profile email`. It uses `preferred_username` (falling back to `sub`) as the user name.

### Authentik

1. **Groups.** Under **Directory → Groups**, create the groups used in your rules and add users to them.
2. **Application.** Under **Applications → Applications → Create with provider**, create an *OAuth2/OpenID Provider*:
   - **Client type:** *Confidential*. Note the client ID and secret.
   - **Redirect URIs:** *Strict*, `https://files.example.com/api/session/auth/`.
   - **Signing key:** pick a certificate, e.g. *authentik Self-signed Certificate*. Without one, tokens are signed with HS256 and rejected.
   - **Scopes:** keep the defaults `openid`, `email` and `profile`. The default `profile` mapping adds `groups`.
   - **Include claims in id_token:** keep it enabled.
3. **Access (optional).** Bind groups to the application to decide who may sign in at all.
4. **Usernames.** Under **System → Settings**, keep *Allow users to change username* off. Filestash tells users apart by their user name.

Your issuer is shown as *OpenID Configuration Issuer*, e.g. `https://auth.example.com/application/o/filestash/`.

## Filestash

Configure Filestash in the admin console at `https://files.example.com/admin`, or in `state/config/config.json`.

### 1. Storage

Add a single `groupfolders` backend with the label `Files`, and remove all others. With exactly one backend behind the identity provider, the login page sends visitors straight to the provider.

### 2. Authentication middleware

In **Storage → Authentication Middleware**, select `oidc`:

| Field | Value |
|---|---|
| `issuer` | `https://auth.example.com/application/o/filestash/` |
| `client_id` | the client ID |
| `client_secret` | `{{ .ENV_OIDC_CLIENT_SECRET }}` |
| `redirect_uri` | `https://files.example.com/api/session/auth/` |

Then map the attributes for `Files`:

| Field | Value |
|---|---|
| `user` | `{{ .user }}` |
| `password` | `{{ .password }}` |

`password` carries the user's sealed groups, not a password.

### 3. Settings

| Setting | Value |
|---|---|
| `features → groupfolders → root` | directory holding the shared directories, default `/mnt/files` |
| `features → groupfolders → rules` | see [Rules](#rules) |
| `features → share → enable` | off: shared links carry their creator's session and would bypass the rules |
| `general → cookie_timeout` | `480`, matching how long group memberships are trusted |

### The same in config.json

```json
{
  "general": { "cookie_timeout": 480 },
  "features": {
    "share": { "enable": false },
    "groupfolders": {
      "root": "/mnt/files",
      "rules": "shared: *\nteam-1: team-1\nprojects: team-1, team-2"
    }
  },
  "connections": [{ "type": "groupfolders", "label": "Files" }],
  "middleware": {
    "identity_provider": {
      "type": "oidc",
      "params": "{\"issuer\":\"https://auth.example.com/application/o/filestash/\",\"client_id\":\"<client id>\",\"client_secret\":\"{{ .ENV_OIDC_CLIENT_SECRET }}\",\"redirect_uri\":\"https://files.example.com/api/session/auth/\"}"
    },
    "attribute_mapping": {
      "related_backend": "Files",
      "params": "{\"Files\":{\"type\":\"groupfolders\",\"user\":\"{{ .user }}\",\"password\":\"{{ .password }}\"}}"
    }
  }
}
```

Both `params` values are JSON-encoded strings. Filestash encrypts them the next time it saves the config.

## Rules

```
# directory: groups (comma separated), * = everyone signed in
shared: *
team-1: team-1
projects: team-1, team-2
finance: accounting
```

- **Matching.** Directories are those right below the root. Directory and group names must match exactly, including case.
- **No rule, no access.** A directory without a rule is hidden from everyone.
- **When changes apply.** Rule changes apply immediately. Group changes at the provider apply at the next sign-in, at the latest after 8 hours.
- **Moving files.** Files can't be moved between two directories. Download and upload them instead.
- **Signing out.** Signing out of Filestash doesn't end the session at the provider. Since the login page goes straight to the provider, users are signed back in right away. To switch users, sign out at the provider.
