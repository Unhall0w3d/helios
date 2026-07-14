# Transport trust

HTTPS collection warns and continues without certificate verification by default
because many Cisco UC deployments use self-signed certificates. Use
`--verify-tls` with the system trust store or `--ca-bundle /path/to/customer-ca.pem`
when the environment supports verified TLS. `--ca-bundle` requires `--verify-tls`.

UCOS SSH rejects unknown host keys by default. In the interactive collection
menu, an unknown key pauses collection and displays its host, algorithm, and
SHA-256 fingerprint. After verifying that fingerprint out of band, choose `y`
to trust and save the key in the local known-hosts store. This applies to nodes
found after CUCM or CUC cluster discovery as well. Direct CLI runs remain
non-interactive and reject unknown keys unless `--accept-new-host-key` is used
after independent fingerprint verification. A changed key remains a failure
requiring review; AletheiaUC never silently accepts one.

These behaviors are fixture-tested. Private-CA and UCOS enrollment outcomes
must still be validated against each customer environment before production use.
