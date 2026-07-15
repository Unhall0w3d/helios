# Security and data handling

Assessment artifacts, JSON reports, run logs, and review ZIPs are private
diagnostic material. On POSIX systems, AletheiaUC-created diagnostic directories
use owner-only permissions and created files use owner-readable/writable
permissions. API and CLI evidence uses the configured `secrets` redaction mode
by default. It redacts common authentication headers and password-, secret-,
token-, and API-key-like values in XML, JSON, and key/value text. Redaction is a
defense in depth, not a guarantee that arbitrary customer data is safe to share;
`none` retains raw evidence and requires deliberate operator care.

Customer-safe HTML is a customer-deliverable report, not an anonymized public
report. It intentionally retains profile and target names, hostnames, IP
addresses, device identifiers, dial-plan values, configuration names and
settings, and finding facts. This allows the customer's engineers to understand
and act on the assessment. It omits private artifact paths, raw evidence,
collection coverage, command-level platform-check records, collector
notes/issues/evidence, and the engineering reconciliation appendix. Review the
rendered HTML before sharing.

CUC detailed CUPI normalization uses per-resource field allowlists and excludes
mailbox/user identities, email addresses, credentials, and message content.
It retains engineering-relevant phone-system, port, routing-target, schedule,
mailbox-store, message-aging, and SMTP configuration values. Linked message-aging
rule collection follows only same-server `/vmrest/` paths returned by the policy API.
Experimental CUC Informix collection accepts no operator-provided SQL. It runs
only fixed `SELECT FIRST 100` queries against `unitydirdb` on the publisher and
rejects statement separators, comments, and mutation/administration keywords.
Normalized results deliberately retain directory extensions, call-handler names,
touch-tone keys, transfer numbers, and target conversations; raw query output is
private diagnostic evidence.
CUCM line, LDAP, routing, and integration names can reveal customer dial plans or
directory structure and are deliberately retained in both HTML editions. JSON
and raw API evidence remain private diagnostic material.

`--customer-safe-report` is retained as the compatible CLI name and applies only
to the HTML presentation. It does not
make adjacent JSON, logs, artifacts, or review ZIPs safe to share. Review every
bundle before external transfer and remove it according to the customer’s data
retention policy.

Artifact and log directories use collision-safe run IDs and are never reused,
preventing concurrent or same-timestamp assessments from mixing their output.
