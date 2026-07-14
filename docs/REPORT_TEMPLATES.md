# HTML Report Templates

Report templates change presentation only. Collection, evidence, findings, and
the customer-deliverable data policy are shared by every template.

## Default dark report

`aletheiauc` remains the default template key for CLI and saved-assessment
compatibility, but its presentation is a generic, text-first dark report. It
has no logo, product naming, imagery, watermark, or required asset pack. The
shared cards, tables, chapter structure, responsive behavior, print behavior,
and report data policy remain unchanged.

## Template discovery

The CLI and interactive menu list only registered templates whose complete
asset packs are present. Review bundles render the same installed set. A missing
optional pack therefore cannot break the default report or a review export.

The generic renderer and shared report structure belong in source control.
Company identity, brand-specific CSS, metadata, and artwork belong in an
external data-only pack. The default installation directory is
`~/.config/aletheiauc/report-templates/`; set
`ALETHEIAUC_REPORT_TEMPLATE_DIR` to use another parent directory. A template
with no asset slots, such as the default dark report, requires no files; an
illustrated or branded template requires its manifest, stylesheet, and every
file declared in its slot map.

## Private company templates

An authorized external `comsource` pack can be selected with:

```bash
./aletheiauc.py --html-template comsource --customer-safe-report
```

Its company name, presentation rules, logo, and artwork are not distributed
with AletheiaUC. The private pack has this layout:

- `comsource/manifest.json`
- `comsource/theme.css`
- `comsource/assets/ComSource_Logo.svg`
- the additional assets declared by the manifest

Install the `comsource` directory directly beneath the external template parent,
for example `~/.config/aletheiauc/report-templates/comsource/manifest.json`.
When every required file exists, it is automatically available to the CLI,
menu, report builder, and review-bundle renderer. An incomplete pack is not
listed, and an explicit programmatic request reports its missing files. Rendered
reports embed installed assets as data URIs and have no external image dependency.

Removing or moving the installed directory disables future generation of that
template. It does not alter standalone reports that were already generated.
Keep private template ZIPs and installed packs out of this repository and public
releases.

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
CUC inventory rows display API totals, normalized rows, page counts, and
complete/partial coverage. Configuration resources are collected in pages up
to the configured CUPI record limit, so a bounded partial result cannot be
mistaken for full inventory. Message-aging rule details include the owning
policy name. Repeated CUC schedule/schedule-set rows with the same normalized name and fields
are grouped with an occurrence count in report details; source facts and private
evidence remain unchanged. CUCM line-group directory numbers and SIP destination
addresses are also recovered through fixed, server-bounded SQL when the standard
AXL object contains only UUIDs or ports.

Diagnostic CUC reports include a separate **Unity Connection Experimental SQL
Validation** table showing each fixed probe's completion status, normalized row
count, and limit. Successful duplicate-extension and call-handler transfer rows
also appear in Unity Connection Configuration with an `experimental` label. The
customer-safe edition intentionally retains extensions, call-handler names,
touch-tone keys, transfer numbers, and target conversations for engineering use;
raw SQL output and artifact paths remain private.
Duplicate extensions produce a warning, while configured alternate-contact and
system-transfer paths produce an informational restriction-table/toll-fraud
review; neither finding is emitted when its experimental probe did not complete.

The default dark report deliberately embeds no images, keeping it compact,
generic, and easy to read. Active service certificates and trust-store entries
are summarized separately so stale trust entries are not presented as proof of
an outage.

## Shared design system

All templates use one semantic report structure with shared `rds-*` components
for the hero, metadata chips, scalable transition, chapter headers, executive
metric groups, findings, recommendations, tables, and footer. Shared components
own layout, information hierarchy, overflow containment, responsive breakpoints,
and print behavior. This ensures that fixes to cards and other report behavior
automatically apply to ComSource and future templates.

Themes provide presentation tokens and map named asset slots onto the shared
components. Each theme therefore retains its own colors, fonts, imagery, logo
rules, and decorative treatment without forking report markup. The slot
contract for themes that use artwork includes:

- `hero-background` and `executive-background`
- `chapter-findings`, `chapter-scope`, `chapter-infrastructure`,
  `chapter-analysis`, and `chapter-evidence`
- `recommendation-background`, `watermark`, and `footer-background`
- `logo-primary` for placements enabled by that theme

A theme may map several slots to one reusable image, as ComSource does with its
local section artwork. A theme may also declare no slots, as the default dark
report does. An installed ComSource pack uses its local official SVG in the
hero and footer. Theme
presentation must not change facts, health logic, severity meaning, or the
customer-deliverable data policy.

The Executive Overview is shared functional content rather than a decorative
number grid. Its four groups cover environment scale, runtime telemetry, risk
signals, and evidence traceability. Every card includes a value, label, state,
and short interpretation. Three-, two-, and one-column layouts use zero-minimum
grid tracks and explicit wrapping so long labels remain within their cards.

Every troubleshooting/review ZIP includes presentation comparisons for all
installed templates, rendered from the same assessment facts. A clean clone
always includes:

- `reports/aletheiauc/engineering.html`
- `reports/aletheiauc/customer-facing.html`

With an authorized external ComSource pack installed, it additionally includes:

- `reports/comsource/engineering.html`
- `reports/comsource/customer-facing.html`

The existing `report.html` and `customer_safe_report.html` remain as compatible
copies of the operator-selected template.
