# leas-dns

Secure DNS resolution for leas via DNSCrypt stamps (DNSCrypt/DoH/DoT/DoQ).

One hickory-resolver pool serves every stamp kind: DoH/DoT/DoQ through
hickory's own transports, DNSCrypt v2 server stamps through the custom
`ConnectionProvider` in `src/dnscrypt.rs`. `DnsResolver::set_candidates` swaps
the pool live (an `ArcSwapOption`, so a lookup in flight finishes on the old
one). The crate persists nothing: it parses (`parse_stamps`), downloads on
request (`fetch_source`) and times (`measure`); the app owns the sources, the
measurements and the top-N selection.

Anonymized DNSCrypt relays and ODoH are not implemented.
