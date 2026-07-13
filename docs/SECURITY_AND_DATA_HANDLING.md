# Security and data handling

Assessment artifacts, JSON reports, run logs, and review ZIPs are private
diagnostic material. On POSIX systems, AletheiaUC-created diagnostic directories
use owner-only permissions and created files use owner-readable/writable
permissions. API and CLI evidence uses the configured `secrets` redaction mode
by default. It redacts common authentication headers and password-, secret-,
token-, and API-key-like values in XML, JSON, and key/value text. Redaction is a
defense in depth, not a guarantee that arbitrary customer data is safe to share;
`none` retains raw evidence and requires deliberate operator care.

Customer-safe HTML pseudonymizes profile, target, node, device, and address
identifiers and omits detailed fact/evidence fields that can contain customer
names. Operational summaries remain. Review the rendered HTML before sharing,
because free-form titles, reasoning, and recommendations are authored report
content rather than raw evidence.

CUC detailed CUPI normalization uses per-resource field allowlists and excludes
mailbox/user identities, email addresses, credentials, and message content.
CUCM line, LDAP, routing, and integration names can still reveal customer dial
plans or directory structure in engineering artifacts. Customer-safe HTML omits
those names and detail fields; JSON and raw API evidence remain private.

`--customer-safe-report` applies only to the HTML presentation. It does not
make adjacent JSON, logs, artifacts, or review ZIPs safe to share. Review every
bundle before external transfer and remove it according to the customer’s data
retention policy.

Artifact and log directories use collision-safe run IDs and are never reused,
preventing concurrent or same-timestamp assessments from mixing their output.
