# Deployment

## Image

`ghcr.io/islpriem/filestash-oidc-plugin` is built for linux/amd64 and has these tags:

| Tag | Content |
|---|---|
| `latest` | the latest tested build |
| `YYYYMMDD` | the monthly rebuild on the latest Filestash, go-oidc and base images |
| `sha-<commit>` | a specific commit |
| `<version>` | a released version, if any |

Filestash has no releases, so the monthly rebuild follows its main branch. Only what the tests cover is checked, so pin a date or `sha-` tag in production rather than `latest`.

For other architectures, build the image yourself:

```sh
git clone https://github.com/islpriem/filestash-oidc-plugin.git
cd filestash-oidc-plugin
docker build -t filestash-oidc .
```

The Filestash commit, go-oidc and base images are pinned in the [Dockerfile](../Dockerfile).

## Compose

```yaml
services:
  filestash:
    image: ghcr.io/islpriem/filestash-oidc-plugin:latest
    restart: unless-stopped
    environment:
      APPLICATION_URL: files.example.com
      OIDC_CLIENT_SECRET: ${OIDC_CLIENT_SECRET}
    ports:
      - "127.0.0.1:8334:8334"
    volumes:
      - ./state:/app/data/state
      - /path/to/files:/mnt/files
```

Put `OIDC_CLIENT_SECRET=...` into a `.env` file next to `compose.yaml`, readable by you only.

Filestash runs as uid 1000. It needs to own `./state` and every directory it serves, so create `./state` before the first start:

```sh
mkdir -p state
sudo chown -R 1000:1000 state /path/to/files/*
```

## Reverse proxy

Serve Filestash over HTTPS behind a reverse proxy. Keep two things in mind:

- **Host header.** `APPLICATION_URL` must match the public host name, and the proxy has to pass the original `Host` header on. Otherwise Filestash rejects API calls.
- **Reaching the provider.** The container must be able to reach the provider's issuer URL. It uses it for discovery, token exchange and signing keys.

Next, [configure](configuration.md) Filestash and your identity provider.
