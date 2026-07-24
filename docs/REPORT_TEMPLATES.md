# HTML Report Templates

Report templates change presentation only. Collection, evidence, findings, and
the customer-deliverable data policy are shared by every template.

## Default dark report

`aletheiauc` remains the reliable fallback template key for CLI and saved-assessment
compatibility. Its presentation is a generic, text-first dark report with no
logo, product naming, imagery, watermark, or required asset pack. When the
complete external `comsource` pack is installed, it is automatically selected
as the default; otherwise this generic dark report is used. The shared
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
`ALETHEIAUC_REPORT_TEMPLATE_DIR` to use another parent directory. A script
run creates the default directory automatically when it is missing, so an
operator can install an approved pack there without first creating folders.
An alternate environment-controlled directory is not created automatically.
A template with no asset slots, such as the default dark report, requires no files; an
illustrated or branded template requires its manifest, stylesheet, and every
file declared in its slot map.

On startup, AletheiaUC also looks in `~/Downloads` for files named
`ComSource-Private-Report-Template-*.zip`. When present, it validates and
installs the newest archive's `comsource` pack into the default template
directory. An unchanged archive is not re-imported; malformed archives are
ignored and cannot replace an installed pack. This convenience import applies
only to the default directory, not an `ALETHEIAUC_REPORT_TEMPLATE_DIR` override.

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
menu, report builder, and review-bundle renderer—and becomes the default
presentation. An incomplete pack is not listed, and an explicit programmatic request reports its missing files. Rendered
reports embed installed assets as data URIs and have no external image dependency.

Removing or moving the installed directory disables future generation of that
template. It does not alter standalone reports that were already generated.
Keep private template ZIPs and installed packs out of this repository and public
releases.

## Create a compatible template pack

An external pack changes presentation only: it cannot add, remove, or alter
assessment facts, health logic, report sections, or the customer-data policy.
Start with a simple text-first theme, validate it, and add artwork only where it
materially improves the report.

### 1. Create this directory layout

Choose a lowercase key made of letters, numbers, `_`, or `-`; this example uses
`northstar`.

```text
~/.config/aletheiauc/report-templates/
└── northstar/
    ├── manifest.json
    ├── theme.css
    └── assets/
        └── logo.svg                 # optional
```

`manifest.json` must be directly inside the key directory. `theme.css` and every
declared asset must be regular files inside that same pack; paths outside the
pack, including `..`, are rejected. The supported artwork formats are SVG, PNG,
JPG/JPEG, and WebP. Assets are embedded in each generated report, so do not use
remote URLs, web fonts, JavaScript, or analytics.

### 2. Use this complete minimal manifest

This pack has no imagery and is valid as soon as `theme.css` exists. All seven
color keys are required even if a stylesheet also sets colors.

```json
{
  "schema_version": 1,
  "key": "northstar",
  "template": {
    "title": "Collaboration Health Assessment",
    "eyebrow": "Customer health report",
    "tagline": "Clear findings and practical next steps",
    "footer_label": "Northstar · Collaboration Health Assessment"
  },
  "theme": {
    "asset_directory": "assets",
    "stylesheet": "theme.css",
    "slots": {},
    "colors": {
      "page": "#16202A",
      "surface": "#203040",
      "text": "#F5F8FA",
      "muted": "#B5C1CB",
      "accent": "#7997B2",
      "cyan": "#70C3D4",
      "gold": "#D7B96F"
    },
    "hero_overlay": "none",
    "hero_focal_point": "center",
    "watermark_opacity": "0",
    "show_hero_logo": false,
    "show_footer_logo": false
  }
}
```

`schema_version` is currently `1`. A pack with an unknown version, an invalid
key, a missing required field, or a missing referenced file is ignored during
discovery rather than breaking report generation. `footer_label` is optional;
all other fields in the example are required.

### 3. Add the stylesheet

`theme.css` is a full presentation stylesheet for the pack; it replaces the
built-in generic-dark stylesheet, while AletheiaUC continues to add the shared
`rds-*` design-system layout afterward. Scope selectors to the template body
class (`<key>-report`) so the theme remains isolated. A minimal usable start is:

```css
body.northstar-report { background: #16202a; color: #f5f8fa; }
.northstar-report .report-shell { width: min(1320px, calc(100% - 40px)); margin: 24px auto 64px; }
.northstar-report .report-hero { padding: 34px 42px 28px; border: 1px solid #40566a; border-radius: 14px; background: #203040; }
.northstar-report main { display: grid; gap: 18px; margin-top: 18px; }
.northstar-report section { margin: 0; border-color: #40566a; background: #203040; }
.northstar-report .meta-chip { border-color: #5c7a93; color: #f5f8fa; }
@media print { body.northstar-report { background: #fff; color: #111; } }
```

Use the shared `rds-*` classes for any further visual refinement. Do not hide
findings, evidence, customer-relevant identifiers, or report sections in the
stylesheet; templates must remain presentation-only.

### 4. Add optional artwork through slots

Put files under `assets/`, then map each used slot to a filename relative to
`asset_directory`. No slots are mandatory. The available slot names are:

- `hero-background`, `executive-background`, `section-band`, and `watermark`
- `chapter-findings`, `chapter-scope`, `chapter-infrastructure`,
  `chapter-analysis`, and `chapter-evidence`
- `recommendation-background`, `footer-background`, and `logo-primary`

For example, add this to `theme.slots` when `assets/logo.svg` exists:

```json
"slots": { "logo-primary": "logo.svg" }
```

Set `show_hero_logo` and/or `show_footer_logo` to `true` only when
`logo-primary` is declared. For photographic backgrounds, use a broad image
with enough quiet space for text and set `hero_focal_point` to a valid CSS
`object-position` value such as `center`, `center right`, or `45% 50%`.

### 5. Install and validate

Copy the complete directory to the template parent, then start AletheiaUC. The
menu and `--html-template` option list the pack only after it validates. A quick
local discovery check is:

```bash
python -c "from cisco_collab_health.reports.html import available_report_templates; print(*available_report_templates(), sep='\\n')"
```

`northstar` should appear in the output. Select it in **Settings**, or run an
assessment with `--html-template northstar`, and inspect both engineering and
customer-facing HTML/PDF outputs. A diagnostic review ZIP renders every complete
installed template, which is the preferred final layout check.

The automatic Downloads import is intentionally reserved for approved
`ComSource-Private-Report-Template-*.zip` archives whose internal directory and
key are both `comsource`. Install all other template packs manually using the
directory layout above.

## Review bundles

With `--export-review-zip`, the private troubleshooting bundle includes the
selected report as `report.html` and a separately rendered,
customer-deliverable `customer_safe_report.html`. This permits side-by-side
review of the customer deliverable while retaining the engineering artifacts in
the same private bundle.

The guided menu always writes both HTML editions. A **standard assessment**
writes the engineering report and adjacent customer-facing report only. A
**diagnostic assessment** also writes artifacts and troubleshooting logs, then
builds the private review ZIP. Both editions use the selected template and the
same assessment facts.

Customer-safe reports use the same assessment facts as engineering reports and
do not use synthetic data. They retain profile and target names, hostnames, IP
addresses, device identifiers, dial-plan values, CUC/CUCM configuration, and
actionable finding facts. This is intentional: the customer audience includes
engineers who need concrete identifiers to understand and act on the assessment.
Private artifact paths, raw evidence, collection coverage, command-level
platform-check records, collector notes/issues/evidence, and the engineering
reconciliation appendix are omitted.

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

### Local PDF rendering prerequisite

Every selected template can also be rendered as engineering and customer-facing
PDF output. This uses Playwright with a local Chromium binary; no report data is
sent to an external rendering service. Installing `requirements.txt` installs
the Playwright Python package, but the browser binary is a separate one-time
install for each virtual environment:

```bash
python -m pip install -r requirements.txt
python -m playwright install chromium
```

Use the same virtual environment for these commands and for AletheiaUC. On a
host where PDF generation is intentionally unavailable, pass
`--no-pdf-report`; the HTML reports and diagnostic bundle are still generated.

With an authorized external ComSource pack installed, it additionally includes:

- `reports/comsource/engineering.html`
- `reports/comsource/customer-facing.html`

The existing `report.html` and `customer_safe_report.html` remain as compatible
copies of the operator-selected template.

The customer edition retains customer-relevant identifiers, configuration, and
actionable findings, while omitting collection-source captions, collection
coverage, and source columns from detailed tables. Engineering editions retain
that provenance for diagnostic review.
