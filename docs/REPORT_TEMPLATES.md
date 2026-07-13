# HTML Report Templates

Report templates change presentation only. Collection, evidence, findings, and
customer-safe masking are shared by every template.

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
always-masked `customer_safe_report.html`. This permits side-by-side review of
the customer deliverable while retaining the engineering artifacts in the same
private bundle.

Customer-safe reports use the same assessment facts as engineering reports.
They do not use synthetic data. They pseudonymize profile, target, node, device,
and address identifiers; omit private artifact paths, detailed device and
registration tables, platform-command details, finding fact strings, and
technical evidence inventories; and retain de-identified findings and summarized
collection coverage needed for review. The pseudonyms are deterministic within
a report so repeated references remain understandable.

Engineering reports expose bounded CUC inventory and sanitized configuration in
separate sections. CUCM configuration reporting includes dedicated expandable
tables for hunt/directory-number topology, trunk/directory/device security, and
media-resource membership. Customer-safe reports retain counts for these areas
while omitting configuration names, dial-plan values, LDAP paths, destinations,
and detailed settings.

The standalone AletheiaUC report embeds only the artwork it actively renders;
the hero image is not duplicated as a section watermark. This keeps the report
self-contained while avoiding unnecessary bundle growth. Active service
certificates and trust-store entries are summarized separately so stale trust
entries are not presented as proof of an outage.

## Shared design system

All templates use one semantic report structure with shared `rds-*` components
for the hero, metadata chips, sections, metrics, findings, tables, and footer.
Themes provide only their tokens and named asset slots. The AletheiaUC template
uses the canonical repository logo; the ComSource template uses the supplied
official SVG unchanged. Theme presentation must not change facts, health logic,
or customer-safe masking.

Every troubleshooting/review ZIP now includes all presentation comparisons,
rendered from the same assessment facts:

- `reports/aletheiauc/engineering.html`
- `reports/aletheiauc/customer-facing.html`
- `reports/comsource/engineering.html`
- `reports/comsource/customer-facing.html`

The existing `report.html` and `customer_safe_report.html` remain as compatible
copies of the operator-selected template.
