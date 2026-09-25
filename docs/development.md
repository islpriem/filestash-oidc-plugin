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

## Updating

[scripts/bump.sh](../scripts/bump.sh) moves the [Dockerfile](../Dockerfile) to the latest Filestash commit, go-oidc release and base image digests. Then run `make test` and `make e2e`. The Go version (`golang:1.26-trixie`) and the GitHub Actions are updated by hand.

## Releases

CI runs both test suites on every push and pull request. Pushes to `main` and `v*` tags publish the tested image to `ghcr.io/islpriem/filestash-oidc-plugin`.

On the first of every month, or when the workflow is started by hand on `main`, CI runs the bump script first. If the tests pass, it commits the new pins and publishes the image as `latest` and `YYYYMMDD`. If they fail, nothing is committed or published. The image is rebuilt even when no pin moved, which picks up security updates of the Debian packages.
