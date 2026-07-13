# HTML Report Templates

Report templates change presentation only. Collection, evidence, findings, and
the customer-deliverable data policy are shared by every template.

## AletheiaUC

`aletheiauc` is the default engineering and customer-deliverable template. Its
identity is documented in [Brand Pack](BRANDING.md).

## ComSource

`comsource` is an optional customer-facing template selected with:

```bash
./aletheiauc.py --html-template comsource --customer-safe-report
```

It uses the user-supplied canonical ComSource logo, which is stored unchanged
at `src/cisco_collab_health/reports/assets/comsource/ComSource_Logo.svg`. The
rendered ComSource report embeds that SVG and its supplied companion artwork as
data URIs, so it does not require external assets.

The ComSource template deliberately contains no AletheiaUC name, marks,
taglines, capability row, or powered-by attribution. Its purple and cyan are
identity/navigation colors; report severity states retain their independent,
text-labeled meanings. The template supports narrow layouts and browser print
preview.

## Review bundles

With `--export-review-zip`, the private troubleshooting bundle includes the
selected report as `report.html` and a separately rendered,
customer-deliverable `customer_safe_report.html`. This permits side-by-side
review of the customer deliverable while retaining the engineering artifacts in
the same private bundle.

Customer-safe reports use the same assessment facts as engineering reports and
do not use synthetic data. They retain profile and target names, hostnames, IP
addresses, device identifiers, dial-plan values, CUC/CUCM configuration,
normalized platform details, finding facts, and technical evidence operations.
This is intentional: the customer audience includes engineers who need concrete
identifiers to understand and act on the assessment. Private artifact paths and
raw evidence content remain omitted.

Engineering reports expose bounded CUC inventory and sanitized configuration in
separate sections. CUCM configuration reporting includes dedicated expandable
tables for hunt/directory-number topology, trunk/directory/device security, and
media-resource membership. Customer-safe reports expose the same operational
configuration names, dial-plan values, LDAP paths, destinations, and settings.
Repeated CUC schedule/schedule-set rows with the same normalized name and fields
are grouped with an occurrence count in report details; source facts and private
evidence remain unchanged. CUCM line-group membership and SIP destinations are
shown only when the expected bounded AXL object was returned.

The standalone AletheiaUC report embeds only the artwork it actively renders;
the hero image is not duplicated as a section watermark or accompanied by a
second logo above the engineering-brief label. The full-width divider between
the hero and executive overview uses a compact 16-pixel display height to avoid
vertical stretching. This keeps the report self-contained while avoiding
unnecessary bundle growth. Active service
certificates and trust-store entries are summarized separately so stale trust
entries are not presented as proof of an outage.

## Shared design system

All templates use one semantic report structure with shared `rds-*` components
for the hero, metadata chips, sections, metrics, findings, tables, and footer.
Themes provide only their tokens and named asset slots. The AletheiaUC template
uses the canonical repository logo; the ComSource template uses the supplied
official SVG unchanged. Theme presentation must not change facts, health logic,
or customer-deliverable data policy.

Every troubleshooting/review ZIP now includes all presentation comparisons,
rendered from the same assessment facts:

- `reports/aletheiauc/engineering.html`
- `reports/aletheiauc/customer-facing.html`
- `reports/comsource/engineering.html`
- `reports/comsource/customer-facing.html`

The existing `report.html` and `customer_safe_report.html` remain as compatible
copies of the operator-selected template.
