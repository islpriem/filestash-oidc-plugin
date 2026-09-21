# filestash-oidc

A [Filestash](https://github.com/mickael-kerjean/filestash) plugin that signs users in through an OpenID Connect provider (tested with Authentik) and decides which folders they see based on the `groups` claim of their ID token.

With `/mnt/files` holding `team-1`, `team-2` and `shared`, and these rules

```
shared: *
team-1: team-1
team-2: team-2
```

a member of the `team-1` group sees `team-1` and `shared` right after signing in. `team-2` doesn't even show up in the listing.

The plugin is compiled into Filestash, so it ships as a Docker image built from the upstream sources plus this plugin.

## How it works

The plugin registers two things with Filestash:

- **`oidc` authentication middleware**
  - Runs the authorization code flow with PKCE, `state` and `nonce`.
  - A short-lived cookie binds the login to the browser that started it.
  - The ID token is verified with [go-oidc](https://github.com/coreos/go-oidc): signature, issuer, audience, expiry, nonce.
- **`groupfolders` storage backend**
  - Serves the folders below a root directory, but only those a rule grants to one of the user's groups.
  - Folders without a rule are hidden from everyone.
  - All access goes through `os.Root`, so symlinks can't lead outside a folder.
  - The root itself is read-only.

After login, the user's groups are sealed with a key derived from the Filestash secret and stored in the session. They can't be forged through the regular login endpoint. The sealed groups are valid for 8 hours; after that, Filestash sends the user through the provider again and picks up group changes. Changes to the rules apply immediately.

## Build

Build the image on the machine that runs it, so the architecture matches:

```sh
git clone <this repository> filestash-oidc && cd filestash-oidc
docker build -t filestash-oidc:$(git rev-parse --short HEAD) .
```

The Filestash version is pinned through `FILESTASH_COMMIT` in the `Dockerfile`. A full build takes a few minutes.

## Deploy

```yaml
services:
  filestash-app:
    image: filestash-oidc:<tag>
    restart: unless-stopped
    environment:
      - APPLICATION_URL=files.example.com
      - OIDC_CLIENT_SECRET=${OIDC_CLIENT_SECRET}
    expose:
      - 8334
    volumes:
      - ./volumes/filestash:/app/data/state/
      - /mnt/files:/mnt/files
    networks:
      - webproxy

networks:
  webproxy:
    external: true
```

- **Client secret.** Put `OIDC_CLIENT_SECRET=...` in a `.env` file next to `compose.yaml` and `chmod 600` it.
- **File ownership.** Filestash runs as uid 1000, so the shared folders have to belong to it:

  ```sh
  sudo chown -R 1000:1000 /mnt/files/team-1 /mnt/files/team-2
  ```

- **Host header.** `APPLICATION_URL` must be the public host name, and the reverse proxy has to pass the original `Host` header through, or Filestash rejects API calls.
- **Reaching the provider.** The container must be able to reach the provider's issuer URL for discovery, token exchange and keys.

## Configure Filestash

You can configure everything in the admin console at `https://files.example.com/admin`, or put it into `volumes/filestash/config/config.json`.

### 1. Storage

In **Storage**, remove every storage backend and add a single `groupfolders` backend labelled `Files`. With exactly one backend behind the identity provider, the login page skips its form and sends visitors straight to the provider. Other backends would also let anyone use Filestash to connect to arbitrary servers.

### 2. Authentication middleware

In **Storage → Authentication Middleware**, select `oidc` and fill in the fields:

| Field | Value |
|---|---|
| `issuer` | `https://auth.example.com/application/o/filestash/` |
| `client_id` | client ID from Authentik |
| `client_secret` | `{{ .ENV_OIDC_CLIENT_SECRET }}` |
| `redirect_uri` | `https://files.example.com/api/session/auth/` |

Then map the attributes for `Files`:

| Field | Value |
|---|---|
| `user` | `{{ .user }}` |
| `password` | `{{ .password }}` |

`password` isn't a password here. It carries the user's sealed groups.

### 3. Settings

| Setting | Value |
|---|---|
| `features → groupfolders → root` | directory holding the shared folders (default `/mnt/files`) |
| `features → groupfolders → rules` | one folder per line, see below |
| `features → share → enable` | `off`. Shared links carry the session of whoever created them, stop working after 8 hours and bypass the rules for anyone holding the link. |
| `general → cookie_timeout` | `480`, so the browser session ends together with the sealed groups |

### The same as config.json

```json
{
  "general": { "cookie_timeout": 480 },
  "features": {
    "share": { "enable": false },
    "groupfolders": {
      "root": "/mnt/files",
      "rules": "shared: *\nteam-1: team-1\nteam-2: team-2"
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

Both `params` values are JSON encoded strings. Filestash encrypts them the next time it saves the config.

## Rules

```
# folder: groups (comma separated), * = everyone signed in
shared: *
team-1: team-1
projects: team-1, team-2
finance: accounting
```

- **Matching.** Folder names are the directories right below the root. Folder and group names are matched exactly, including case.
- **Several groups.** A folder can be granted to several groups.
- **Everyone signed in.** `*` shares a folder with every signed-in user.
- **No rule, no access.** A folder without a rule, or a rule pointing to a folder that doesn't exist, shows nothing.
- **Moving files.** Files can't be moved between two folders; download and upload them instead.

To add a folder, create the directory, `chown` it to uid 1000 and add a line to the rules.

## Authentik

1. **Groups.** Under **Directory → Groups**, create the groups used in the rules (e.g. `team-1`, `team-2`) and add the users to them.
2. **Application.** Under **Applications → Applications**, choose **Create with provider**:
   - **Application:** name `Filestash`, slug `filestash`, launch URL `https://files.example.com/`.
   - **Provider type:** OAuth2/OpenID Provider.
   - **Client type:** Confidential. Copy the client ID and client secret.
   - **Redirect URIs:** `Strict`, `https://files.example.com/api/session/auth/`.
   - **Signing key:** pick a certificate, e.g. *authentik Self-signed Certificate*. Without one, Authentik signs with HS256, which the plugin doesn't accept.
   - **Advanced protocol settings:**
     - Keep the scopes `openid`, `email` and `profile`. The default `profile` mapping adds the `groups` claim.
     - Leave **Include claims in id_token** enabled.
3. **Access (optional).** Bind the groups that may use Filestash to the application, so everyone else is turned away by Authentik.
4. **Issuer.** Take the issuer from the provider's overview (*OpenID Configuration Issuer*). It looks like `https://auth.example.com/application/o/filestash/`.

**Signing out.** Signing out of Filestash doesn't end the Authentik session. Since the login page sends visitors straight to the provider, you're signed back in right away. To switch users, sign out of Authentik.

## Development

Everything runs in Docker:

```sh
make test      # unit tests, inside the pinned Filestash tree
make e2e       # builds the image, starts Filestash with a mock OpenID provider and runs the end-to-end tests
make e2e-up    # same stack, left running on http://localhost:8334
make e2e-down
```

- **Test users.** The mock provider in `e2e/` signs in any user name. `alice`, `bob`, `carol`, `dave` and `mallory` have groups set up in `e2e/idp.json`.
- **Updating Filestash.** Change `FILESTASH_COMMIT` in the `Dockerfile`, then run `make test` and `make e2e`.
