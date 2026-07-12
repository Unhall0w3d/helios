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
