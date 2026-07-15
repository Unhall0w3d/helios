# Transport trust

HTTPS collection warns and continues without certificate verification by default
because many Cisco UC deployments use self-signed certificates. Use
`--verify-tls` with the system trust store or `--ca-bundle /path/to/customer-ca.pem`
when the environment supports verified TLS. `--ca-bundle` requires `--verify-tls`.

UCOS SSH rejects unknown host keys by default. In the interactive collection
menu, an unknown key pauses collection and displays its host, algorithm, and
SHA-256 fingerprint. After verifying that fingerprint out of band, choose `y`
to trust and save the key in the local known-hosts store. This applies to nodes
found after CUCM or CUC cluster discovery as well. Direct CLI runs reject
unknown keys unless `--accept-new-host-key` is used; that flag presents the
same approval prompt and never accepts a key automatically. A changed key
remains a failure requiring review; AletheiaUC never silently accepts one.

These behaviors are fixture-tested. Private-CA and UCOS enrollment outcomes
must still be validated against each customer environment before production use.

## SSH collection execution

Before CLI collection, AletheiaUC opens and closes an SSH shell for each
discovered UCOS node sequentially. This ensures unknown-key approval prompts
and writes to `known_hosts` are never interleaved. Nodes that fail key approval,
authentication, or shell setup are excluded from CLI collection and reported as
preflight warnings. Once this phase completes, independent nodes are collected
in parallel (three workers by default) using strict saved-key validation only;
commands within each node's shell remain strictly sequential. Use
`--ssh-parallel-workers 1` to disable node-level parallelism, or choose another
bounded worker count for a suitable environment.

If this preflight receives an SSH authentication failure, an interactive run
offers one node-specific Platform/CLI password retry. The replacement is used
only for that normalized node address. When credential saving is enabled, a
verified replacement is saved separately in the operating-system credential
store for that profile and technology; it is never written to the profile file
or assessment artifacts. With credential saving disabled (or no credential
store available), it is used only for the current run. Key, network, and shell
failures do not trigger a password prompt.
