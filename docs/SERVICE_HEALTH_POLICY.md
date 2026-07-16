# Service health policy

Service findings are deployment-aware: an inactive optional service is not itself an incident. AletheiaUC evaluates only services collected successfully and distinguishes an expected inactive state from a stopped required service.

## Unity Connection

`show cuc cluster status` is normalized into per-node role facts. A two-node steady state normally has one **Primary** and one **Secondary**; a Subscriber acting as Primary is a valid failover condition. Multiple Primary roles, no Primary in a two-node cluster, or a Not Functioning node is critical. Starting, Replicating Data, and Split Brain Recovery are presented as observed transitional states, not asserted as persistent failures from a single snapshot.

The CUC service policy evaluates the collected active nodes for DB, DB Replicator, Tomcat, Connection Conversation Manager, and Connection Mixer. It evaluates Connection Message Transfer Agent and Connection Notifier on the observed Primary. Mailbox Sync and other integration services remain feature-dependent and are not generically marked failed.

Cisco references: [CUC services](https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/connection/14/serv_administration/guide/b_14cucservag/b_14cucservag_chapter_0100.html), [CUC cluster roles](https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/connection/12x/install_upgrade/guide/b_12xcuciumg/b_12xcuciumg_chapter_011.html).

## CUCM

CUCM service activation depends on Publisher, call-processing Subscriber, dedicated TFTP, and enabled-feature roles. AletheiaUC normalizes collected `utils service list` output and evaluates only high-confidence conditions: no Cisco TFTP on any collected CLI node, a stopped activated CallManager, or stopped RIS/Data Layer Monitor where CallManager is running. Optional or unactivated feature services remain informational. CLI coverage is always stated before an activation change is recommended.

Cisco reference: [CUCM service recommendations](https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/admin/15/adminGd/cucm_b_administration-guide-15/cucm_b_test-adminguide_chapter_010111.html).
