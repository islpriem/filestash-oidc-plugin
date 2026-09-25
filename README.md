# filestash-oidc-plugin

An opinionated, simple and minimal [Filestash](https://github.com/mickael-kerjean/filestash) plugin: sign in with OpenID Connect and see only the directories your groups may access.

- Sign-in through an OpenID Connect provider (tested with Authentik), using PKCE, state and nonce
- One rule per directory, e.g. `projects: team-1, team-2`, or `*` for everyone signed in
- Directories without a rule stay hidden, and symlinks can't lead out of a directory
- Visitors go straight to the provider, without a Filestash login form

> This is a small community plugin built on top of Filestash. For production use, consider the officially maintained [Filestash enterprise plugins](https://www.filestash.app/pricing/). They implement a superset of what this plugin does.

## Usage

```sh
docker pull ghcr.io/islpriem/filestash-oidc-plugin:latest
```

The image is Filestash with this plugin compiled in (linux/amd64). It is rebuilt every month on the latest Filestash.

- [Deployment](docs/deployment.md)
- [Configuration](docs/configuration.md)
- [Development](docs/development.md)

## License

[AGPL-3.0](LICENSE), like Filestash.
