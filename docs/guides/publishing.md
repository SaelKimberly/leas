# Publishing

How to release the workspace to crates.io and in what order. It does not cover
building (see `building.md`) or the crates' APIs.

Every member is `0.1.0` from `[workspace.package]`. The workspace-hack
(`leas-hakari`) stays `publish = false`, so release every crate with:

```sh
cargo hakari publish -p <crate>
```

Plain `cargo publish` is rejected because every member depends on the
local-only hack.

## Order (topological: dependencies first)

```text
leas-proto → leas-tls → leas-dns → leas-geoip → leas-host-features
          → leas-route → leas-db → leas-core → leas-config → leas-native → leas
```

The edges this order satisfies, from the manifests:

| Crate | Internal dependencies |
| --- | --- |
| `leas-proto` | none |
| `leas-tls` | none |
| `leas-dns` | none |
| `leas-geoip` | none |
| `leas-host-features` | none |
| `leas-route` | `leas-tls`, `leas-dns` (feature `dns`), `leas-geoip` (feature `geoip`) |
| `leas-db` | `leas-proto` |
| `leas-core` | `leas-db`, `leas-proto` |
| `leas-config` | `leas-proto` |
| `leas-native` | `leas-proto`, `leas-tls`, `leas-route` |
| `leas` | `leas-core`, `leas-db`, `leas-config`, `leas-proto`, `leas-route`, `leas-geoip`, `leas-dns`, `leas-host-features`, `leas-native` |

## Offline proof (leaf crates only)

`cargo package` resolves internal path dependencies against the registry, so it
can prove only crates whose sole internal dependency is the hack. Temporarily
drop the hack edges:

```sh
cargo hakari remove-deps
for c in leas-proto leas-tls leas-dns leas-geoip leas-host-features; do
  cargo package -p "$c" --allow-dirty --no-verify
done
cargo hakari manage-deps   # restore
```

Non-leaf crates are provable only in the staged publish order above, or against
a local registry.
