# ddi_ideas.md

## IP Usage Dashboard by Site

Group normalized IPs by site location to visualize utilization across the network. Display how many IP addresses are assigned at each location such as BLR Campus, HQ, and Lab facilities. This enables capacity planning by identifying which sites are experiencing growth and may require additional address space allocation, while also revealing underutilized locations where resources could be reclaimed.

---

## Find Devices Without Owners

Generate automated compliance reports identifying all devices where owner email field is empty. Every network asset should have an accountable owner for security and compliance purposes. This directly supports SOC 2 and ISO 27001 audit requirements by ensuring asset ownership accountability and providing remediation lists for network administrators to assign missing ownership information.

---

## Network Change Alerts

Store daily inventory snapshots and automatically detect changes by comparing current normalized inventory against previous day's data. When devices appear, disappear, or change configuration, send email alerts to network team. This provides rapid detection of unauthorized network modifications, equipment failures, or shadow IT within 24 hours rather than waiting for quarterly audits or user-reported issues.

---

## Automated Anomaly Tickets

Transform the anomalies.json output into actionable work items by automatically creating tickets in Jira or ServiceNow. Each detected issue such as invalid IP addresses, missing MAC addresses, or RFC violations becomes a tracked ticket with recommended remediation steps. This ensures data quality problems don't get ignored and provides visibility into resolution progress across the network operations team.