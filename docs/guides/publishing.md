# Publishing

The workspace is publishable to crates.io. The workspace-hack (`leas-hakari`) stays
`publish = false`; **release every crate with `cargo hakari publish -p <crate>`** (plain
`cargo publish` is rejected because every member depends on the local-only hack).

## Order (topological — dependencies first)

```
leas-proto → leas-tls → leas-dns → leas-geoip → leas-host-features
          → leas-route → leas-db → leas-core → leas-config → leas-native → leas
```

## Offline proof (leaf crates only)

`cargo package` resolves internal path-deps against the registry, so it can only prove crates
whose sole internal dependency is the hack. Temporarily drop the hack edges:

```
cargo hakari remove-deps
for c in leas-proto leas-tls leas-dns leas-geoip leas-host-features; do
  cargo package -p "$c" --allow-dirty --no-verify
done
cargo hakari manage-deps   # restore
```

Non-leaf crates are provable only in the staged publish order above (or against a local registry).
