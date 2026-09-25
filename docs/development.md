# Development

Everything runs in Docker:

```sh
make test      # unit tests, run inside the pinned Filestash source tree
make e2e       # builds the image, starts Filestash with a mock OpenID provider and runs the end-to-end tests
make e2e-up    # the same stack, left running on http://localhost:8334
make e2e-down
```

The mock provider in `e2e/` signs in any user name. The users `alice`, `bob`, `carol`, `dave` and `mallory` have groups set up in [e2e/idp.json](../e2e/idp.json).

## Layout

The plugin lives in `plg_authenticate_oidc/`. At build time it is copied into the Filestash source tree:

| File | Contents |
|---|---|
| `oidc.go` | the `oidc` authentication middleware |
| `folders.go` | the `groupfolders` storage backend |
| `config.go` | settings and rules |
| `index.go` | registration and sealing of values with a key derived from the Filestash secret |

## Updating Filestash

Change `FILESTASH_COMMIT` in the [Dockerfile](../Dockerfile), then run `make test` and `make e2e`.

## Releases

CI runs both test suites on every push and pull request. Pushes to `main` and `v*` tags publish the tested image to `ghcr.io/islpriem/filestash-oidc-plugin`.
