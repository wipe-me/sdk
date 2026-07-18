# SDK release compatibility

Wipe.me SDKs use a synchronized feature train across ecosystems. Ecosystem-specific
pre-release spelling differs, but the feature version has the same meaning.

| Train | JavaScript / npm | Go module | Python / PyPI | Capability baseline |
|---|---|---|---|---|
| 0.1 | `0.1.0-alpha.1` | `v0.1.0-alpha.1` | — | Links and opaque HTTP operations |
| 0.2 | `0.2.0-alpha.1` | `v0.2.0-alpha.1` | — | Client-side v1 encryption |
| 0.3 | `0.3.0-alpha.1` | `v0.3.0-alpha.1` | `0.3.0a1` | Configurable framing and byte progress |

Starting with train 0.3, a feature release advances all maintained language SDKs
together after the shared fixtures pass. The encrypted wire format remains separately
versioned as protocol v1; package versions do not change the protocol version.
