# Engineering Hardening — Current-State Gap Analysis

Historical Phase 0 snapshot reviewed on 2026-07-12 against `main` at
`6b1b596c08cafee4c8149c12c3e81be7877e55e6`. Later hardening commits supersede
the original matrix statuses. The matrix below was reconciled with the current
implementation on 2026-07-13.
The historical `03102c2` overlay was reviewed only as a source of hypotheses; none of
its replacement files were applied.

## Preflight

- Python: `.venv/bin/python` reports Python 3.14.6. The installed editable package points
  to another workspace, so source-tree tests use `PYTHONPATH=src`.
- Current verification: `PYTHONPATH=src .venv/bin/python -m unittest discover -s tests`,
  `.venv/bin/ruff check src tests`, and `PYTHONPATH=src .venv/bin/python -m mypy src`.
- Packaging validation builds both sdist and wheel; CI installs and smoke-tests the wheel.

## Gap matrix

| Area | Classification | Current evidence and relevant symbols | Follow-up phase |
| --- | --- | --- | --- |
| Collector failure isolation | Resolved | `AssessmentEngine.run` and `TargetPipelineCollector.collect` both use `collect_safely`; only explicitly non-recoverable target errors stop later child collectors. | 1 |
| Package runtime dependencies | Resolved | Paramiko is declared in both `requirements.txt` and `[project].dependencies`. | 1 |
| CI/release artifact verification | Resolved | CI tests Python 3.11/3.13, builds artifacts, installs the wheel in a clean environment, and smoke-tests commands and packaged assets. | 1 |
| Artifact permissions/redaction/bundle metadata | Resolved with operational caveat | POSIX permissions are private, API/CLI evidence applies default structured secret redaction, run IDs are collision-safe, and bundle manifests carry sensitivity/trust metadata. Operators must still review private diagnostic bundles. | 2 |
| HTTPS/SSH trust defaults | Documented policy | HTTPS verification remains disabled by default for self-signed UC environments. SSH rejects unknown keys unless the operator explicitly enables first-use enrollment. | 3 |
| Documentation and governance | Resolved for current scope | Security/data handling, transport trust, collector safety, report templates, branding, and modularization guidance are linked from README. | 4 |
| Module decomposition | Outstanding, intentionally deferred | `reports/html.py`, `config.py`, `application.py`, and `rules/basic.py` remain responsibility-dense. No safe broad move is required for hardening. | 5 plan only |
| UCOS command catalog | Resolved for CUC | `collectors.cuc_platform.CUC_COMMAND_CATALOG` provides stable IDs, command text, per-command timeouts, diagnostic-only scope, and sensitivity metadata. | 5 |
| CUC/CUCM configuration depth | Implemented; live validation required | Bounded CUPI configuration GETs and extended AXL hunt, forwarding, integration-security, LDAP, and media-resource discovery feed dedicated report tables. CUC Informix SQL remains deferred pending version fixtures and load validation. | validation |
| Product/package naming | No longer an immediate hardening defect | Public product and default command are AletheiaUC; distribution/import aliases remain compatibility debt. Do not rename package in this initiative. | 4 documentation |

## Dependency ordering and risks

1. Collector isolation, package metadata, and CI establish a trustworthy verification base.
2. Artifact handling must precede report/log bundle sharing guidance.
3. Transport defaults require explicit operator migration guidance and must not be hidden in a refactor.
4. Documentation is updated with each behavioral phase and reconciled after them.
5. Large-module moves remain separate from security-default changes.

## Live validation still required

- CUCM HTTPS with system trust, private CA, rejected self-signed certificate, hostname mismatch,
  expired certificate, and explicit insecure override.
- CUC UCOS known-host success, unknown-host rejection, verified first-use enrollment, and changed-key rejection.
- Extended UCOS command completion and partial-output behavior on real CUC versions.
- CUPI field-name and endpoint variants across supported CUC versions, including SMTP availability before 14SU2.
- Extended AXL object/returned-tag compatibility and relationship shapes across CUCM 11.5 through 15.
- File permission behavior on Windows and operational review-ZIP sharing workflow.
