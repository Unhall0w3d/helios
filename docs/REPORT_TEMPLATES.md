# HTML Report Templates

Report templates change presentation only. Collection, evidence, findings, and
the customer-deliverable data policy are shared by every template.

## AletheiaUC

`aletheiauc` is the default engineering and customer-deliverable template. Its
identity is documented in [Brand Pack](BRANDING.md). Its complete asset pack is
tracked in the repository, so it is always available on a clean clone.

## Template discovery

The CLI and interactive menu list only registered templates whose complete
asset packs are present. Review bundles render the same installed set. A missing
optional pack therefore cannot break the default report or a review export.

Template behavior—metadata, design tokens, asset-slot mappings, and shared
rendering code—belongs in source control. Partner or customer artwork does not.
Local packs live under `src/cisco_collab_health/reports/assets/<template>/`;
all such directories except `aletheiauc` are ignored by Git and excluded from
package data. Adding a future template requires a registered code definition and
a complete local pack matching its slot map.

## ComSource

`comsource` is an optional customer-facing template selected with:

```bash
./aletheiauc.py --html-template comsource --customer-safe-report
```

Its backing rules and shared layout remain in the repository. Its logo and
artwork stay local at `src/cisco_collab_health/reports/assets/comsource/` and
must not be committed. A complete pack contains:

- `ComSource_Logo.svg`
- `hero-background.svg`
- `section-band.svg`
- `divider-horizontal.svg`
- `watermark.svg`
- `footer-background.svg`
- `status-icons.svg`

When all required files exist, `comsource` is automatically available to the
CLI, menu, report builder, and review-bundle renderer. If an operator explicitly
requests a registered but incomplete template through code, the builder reports
the missing files and local pack directory. Rendered reports embed installed
assets as data URIs and have no external image dependency.

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
CUC inventory rows display API totals, normalized rows, and complete/partial
coverage so a 500-row cap cannot be mistaken for full inventory. Message-aging
rule details include the owning policy name. Repeated CUC schedule/schedule-set
rows with the same normalized name and fields
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

The standalone AletheiaUC report embeds only the artwork it actively renders.
The hero image is not duplicated as a section watermark, and the footer omits a
redundant logo. A code-native SVG transition connects the hero to the executive
overview without stretching raster artwork. Chapter and executive artwork is
stored at its intended display ratio and rendered with `cover`, never resized by
independent width and height rules. This keeps the report self-contained while
avoiding unnecessary bundle growth. Active service
certificates and trust-store entries are summarized separately so stale trust
entries are not presented as proof of an outage.

## Shared design system

All templates use one semantic report structure with shared `rds-*` components
for the hero, metadata chips, scalable transition, chapter headers, executive
metric groups, findings, recommendations, tables, and footer. Shared components
own layout, information hierarchy, overflow containment, responsive breakpoints,
and print behavior. This ensures that fixes to cards and other report behavior
automatically apply to ComSource and future templates.

Themes provide presentation tokens and map named asset slots onto the shared
components. Each theme therefore retains its own colors, fonts, imagery, logo
rules, and decorative treatment without forking report markup. The current slot
contract includes:

- `hero-background` and `executive-background`
- `chapter-findings`, `chapter-scope`, `chapter-infrastructure`,
  `chapter-analysis`, and `chapter-evidence`
- `recommendation-background`, `watermark`, and `footer-background`
- `logo-primary` for placements enabled by that theme

A theme may map several slots to one reusable image, as ComSource does with its
local section artwork, or provide purpose-built imagery for every slot, as
AletheiaUC does. AletheiaUC intentionally has no footer logo; an installed
ComSource pack uses its local official SVG in the hero and footer. Theme
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

With the complete local ComSource pack installed, it additionally includes:

- `reports/comsource/engineering.html`
- `reports/comsource/customer-facing.html`

The existing `report.html` and `customer_safe_report.html` remain as compatible
copies of the operator-selected template.
