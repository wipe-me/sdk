# Wipe.me SDKs

Official JavaScript, Python, and Go implementations of the Wipe.me end-to-end
encrypted, self-destructing messaging protocol and API.

> Development preview: the protocol and packages have not received an
> independent security audit. Do not use preview releases for high-risk data.

## Repository layout

- `specification/` is the canonical cryptographic and interoperability contract.
- `fixtures/` contains language-neutral vectors consumed by every implementation.
- `javascript/` is the `@wipe-me/sdk` npm package.
- `python/` is the `wipe-me` PyPI distribution (`import wipeme`).
- `go/` is the `github.com/wipe-me/sdk/go` module.
- `scripts/` contains checks for copies maintained in the web and CLI repositories.

All three language packages implement shared link/Base58 behavior and compatible
create, retrieve, delete, and health API clients with typed errors. All three 0.3
alphas implement fixture-backed v1 envelope encryption, decryption, configurable
framing, byte progress, secure capability generation, and deletion-key derivation.

Local SDK tests should run in prebuilt language containers so contributors do not need
to install runtimes globally. CI uses the same major runtime versions.

## Development

```bash
docker run --rm -v "$PWD:/sdk" -w /sdk/javascript node:22-bookworm-slim npm test
docker run --rm -v "$PWD:/sdk" -w /sdk/python python:3.12-slim python -m unittest discover -s tests
docker run --rm -v "$PWD:/sdk" -w /sdk/go golang:1.23 go test ./...
node scripts/check-workspace-consistency.mjs /path/to/Wipe.me-workspace
```

Apache-2.0 licensed. See [LICENSE](LICENSE).

See [the synchronized SDK version matrix](specification/version-matrix.md) for the
cross-language capability baseline.
