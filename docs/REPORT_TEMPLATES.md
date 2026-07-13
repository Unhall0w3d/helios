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
They do not use synthetic data; instead they mask saved target/profile labels
and private artifact paths, preserve operational node, device, and address data
needed for customer understanding, omit detailed technical evidence inventories,
and retain the findings and summarized collection coverage needed for review.
