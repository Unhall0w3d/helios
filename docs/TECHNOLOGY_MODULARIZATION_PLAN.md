# Technology Modularization Plan

## Objective

Load and run only the collectors, parsers, rules, and report sections relevant to
the technologies selected for an assessment, while retaining shared transports,
facts, artifact handling, and report composition.

This adopts the useful convention from the legacy health-check project: technology
parsers live with their technology and are called only when that technology is in
scope. This is technology-scoped loading, not forced Python module unloading.
Collectors must still close HTTP and SSH resources immediately after collection.

## Target architecture

```text
technologies/
  cuc/
    collectors.py
    parsers.py
    rules.py
    report_sections.py
  cucm/
    collectors.py
    parsers.py
    rules.py
    report_sections.py
  cer/ …
  imp/ …
shared/
  transport/
  artifacts/
  facts/
  report_shell/
```

Each technology package owns only technology-specific API callers, command
catalogues, parsers, rules, and optional report sections. Shared code owns the
common collection contract, bounded transport sessions, normalized fact models,
artifact retention, report shell, and customer-safe policy.

## Phase 1: Explicit technology plugins

- Replace eager imports in the collector registry with a small manifest keyed by
  technology (`cucm`, `cuc`, `cer`, `imp`).
- Each plugin exposes its collector factory, applicable rules, report-section
  provider, and capability requirements.
- Import a plugin only after an in-scope target selects that technology.
- Do not import or initialize CUCM SOAP clients/parsers for a CUC-only run, or
  CUC CLI parsers for a CUCM-only run.
- Keep the current `TargetPipelineCollector` as the common multi-target boundary.
- A plugin hands normalized facts and evidence to the shared assessment engine;
  downstream rules and reports do not retain client/session objects.

## Phase 2: Shared UCOS CLI collection

- Extract the prompt-aware session loop, command catalogue model, artifact
  writing, timeout retention, and normalized command-result handling from the
  CUC collector into a technology-neutral UCOS CLI module.
- Define technology-specific command catalogues and parsers separately. The
  shared runner must not import CUCM or CUC parsers unless that catalogue is
  selected.
- Add CUCM CLI coverage incrementally and validate each command against fresh
  artifact bundles before promoting its parsed results into health findings.

## Phase 3: Technology-owned facts and rules

- Retain cross-technology facts such as nodes, certificates, platform checks,
  and service status in the shared model package.
- Place CUCM, CUC, CER, and IM&P rule sets in dedicated technology modules.
- Apply only the selected technologies' rule sets plus universal rules such as
  collection health and report coverage.
- Encode role/topology expectations as named policies, rather than treating all
  stopped services or all singleton services identically.

## Phase 4: Report composition

- Register report sections through the same technology plugins.
- Render common sections once and append only the in-scope technology sections.
- Keep customer-safe behavior at the report-policy layer so each plugin provides
  facts, not separate customer and engineering parsers.

## Phase 5: Verification and migration

- Add isolated plugin tests and a matrix test for CUCM-only, CUC-only, mixed
  CUCM+CUC, and repeated technology targets.
- Preserve artifact paths and JSON schemas during extraction.
- Migrate one technology at a time, beginning with CUC because its bounded CLI
  catalogue and live artifacts already exercise the shared execution pattern.
