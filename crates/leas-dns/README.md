# leas-dns

Secure DNS resolution for leas via DNSCrypt stamps (DNSCrypt/DoH/DoT/DoQ).

One hickory-resolver pool serves every stamp kind: DoH/DoT/DoQ through
hickory's own transports, DNSCrypt v2 server stamps through the custom
`ConnectionProvider` in `src/dnscrypt.rs`. Anonymized DNSCrypt relays and ODoH
are not implemented.
