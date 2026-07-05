![AletheiaUC](../assets/brand/png/aletheiauc-repo-header.png)

# AletheiaUC Brand Pack

## Final direction

**Truth Constellation — Beacon Horizon** is the working brand direction for AletheiaUC.

The mark uses a constellation-built **A** to connect the Aletheia theme of truth, disclosure, and unconcealedness with the practical purpose of the tool: surfacing real UC system health from telemetry, command output, tests, and context. The horizon/beacon motif represents making hidden platform state visible.

## Core tagline

**Bringing UC Health to Light**

## Capability row

Use this row consistently where space allows:

**Assess · Diagnose · Improve · Optimize**

These are preferable to purely philosophical terms in UI/product copy because they describe what the CLI does or is intended to do.

## Values and product descriptors

Use the five theme words only when paired with grounded product meaning:

| Value | Product meaning |
|---|---|
| Truth | Surface real system health with data-driven tests and plain-language reporting. |
| Transparency | Make communications health visible with open methods and clear results. |
| Insight | Turn findings into actionable insight to prioritize fixes that matter most. |
| Reliability | Built for consistent, repeatable diagnostics you can count on. |
| Outcomes | Drive better experiences and performance across the UC environment. |

## Color palette

| Name | Hex | Usage |
|---|---:|---|
| Midnight | `#0A0F1E` | Primary dark background |
| Violet | `#6A4CFF` | Constellation accents, secondary highlights |
| Blue | `#2F7CFF` | UC wordmark, links, primary UI highlight |
| Cyan | `#22D3EE` | Diagnostic/telemetry accents |
| Horizon Gold | `#FFC75E` | Beacon/horizon accent, tagline |
| Warm Gold | `#FFB84D` | Secondary gold glow/icon accents |
| Light | `#E6E8F1` | Primary foreground text |

## Asset guidance

### CLI tool

AletheiaUC is currently CLI-first. Recommended CLI usage:

- Use ASCII/ANSI text for the runtime banner by default.
- Use graphical assets only in documentation, release pages, README content, and GitHub assets.
- Keep color usage in terminal output functional: green for success, yellow for warning/auth issues, red for failed connectivity, cyan/blue for headings.
- Do not require image-rendering terminal support.

Recommended CLI banner text:

```text
AletheiaUC
Bringing UC Health to Light
Assess · Diagnose · Improve · Optimize
```

### GitHub / README

Recommended README placement:

```markdown
<p align="center">
  <img src="assets/brand/png/aletheiauc-readme-header.png" alt="AletheiaUC — Bringing UC Health to Light" width="100%">
</p>
```

Recommended social preview upload:

```text
assets/brand/png/aletheiauc-github-social-preview.png
```

### Documentation

Use the repo header at the top of longer docs:

```markdown
![AletheiaUC](../assets/brand/png/aletheiauc-repo-header.png)
```

Use the monochrome mark for simple footers, PDFs, or low-color exports.

## Implementation note: CLI collection direction

Branding should not force terminal behavior. AletheiaUC remains CLI-first, but the project direction is to keep runtime output quiet and progress-oriented while writing raw command output to artifacts for parsing and reporting. Brand assets belong in README, documentation, and release material. Terminal output should remain practical: concise progress, clear statuses, and no raw command-output stream unless verbose/debug mode is explicitly enabled.

## Licensing note

These generated brand assets are included for use with the AletheiaUC project.
If this project becomes public-facing or enters broader commercial use, consider
having the final mark manually redrawn as a clean vector by a designer.
