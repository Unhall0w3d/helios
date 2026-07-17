# Cisco UC lifecycle catalog

The report evaluates lifecycle only when its collected product and resolved Cisco release match a record in the curated catalog at `src/cisco_collab_health/lifecycle.py`. This prevents an unknown release from being presented as either supported or unsupported.

The resolver accepts Cisco's full build text and common shorthand forms—for example, `10.5.2.12901-1`, `v10SU3`, `12.5(1)SU4`, and `v14SU2`. It maps the collected major/minor release to the matching lifecycle notice; the update/SU/build portion does not change a major-release lifecycle notice unless Cisco publishes a more-specific catalog record.

Catalog reviewed: 2026-07-16. Dates are Cisco's published end-of-sale, end-of-software-maintenance, and last-date-of-support milestones. They are planning inputs, not a substitute for validating entitlement, deployment model, or a supported upgrade path with Cisco.

| Technology | Release | End of sale | End of maintenance | Last support | Cisco notice |
| --- | --- | --- | --- | --- | --- |
| CUCM | 10 | 2019-07-02 | 2020-07-01 | 2022-07-31 | [Cisco](https://www.cisco.com/c/en/us/products/collateral/unified-communications/unified-communications-manager-callmanager/eos-eol-notice-c51-741767.html) |
| CUC | 10 | 2019-07-02 | 2020-07-01 | 2022-07-31 | [Cisco](https://www.cisco.com/c/en/us/products/collateral/unified-communications/unity-connection/eos-eol-notice-c51-741765.html) |
| CER | 10 | 2019-07-02 | 2020-07-01 | 2022-07-31 | [Cisco](https://www.cisco.com/c/en/us/products/collateral/unified-communications/emergency-responder/eos-eol-notice-c51-741766.html) |
| CUCM, CUC, CER, IM&P | 11.5 | 2021-05-31 | 2022-05-31 | 2024-05-31 | [Cisco](https://www.cisco.com/c/en/us/products/collateral/unified-communications/unified-communications-manager-callmanager/eos-eol-notice-c51-744533.html) |
| CUCM | 12.0 | 2020-08-17 | 2021-08-17 | 2023-08-31 | [Cisco](https://www.cisco.com/c/en/us/products/collateral/unified-communications/unified-communications-manager-callmanager/eos-eol-notice-c51-743485.html) |
| CER | 12.0 | 2020-08-17 | 2021-08-17 | 2023-08-31 | [Cisco](https://www.cisco.com/c/en/us/products/collateral/unified-communications/emergency-responder/eos-eol-notice-c51-743484.html) |
| CUCM, CUC, CER, IM&P | 12.5 | 2023-08-31 | 2024-08-31 | 2025-08-31 | [Cisco](https://www.cisco.com/c/en/us/products/collateral/unified-communications/unified-communications-manager-callmanager/v-12-5-on-premises-calling-applications-eol.html) |
| CUCM, CUC, CER, IM&P | 14 | 2025-04-07 | 2026-04-07 | 2027-04-30 | [Cisco](https://www.cisco.com/c/en/us/products/collateral/unified-communications/unified-communications-manager-callmanager/v-14-premises-flex-subscriptions-eol.html) |

## Deliberate gaps

The catalog does not infer dates. For the current 15.x release family, the report explicitly shows **End of sale / end of life / end of support not yet available** until Cisco publishes the relevant lifecycle notice. Other absent records render as **Not cataloged — no lifecycle conclusion**. Add dates and the source URL only after verifying the exact product/release against Cisco's official lifecycle notice; update this document in the same change.

The report prioritizes attention when Cisco support has ended, software maintenance has ended, or support ends within 180 days. It links the matching Cisco notice directly in the Software Lifecycle section.
