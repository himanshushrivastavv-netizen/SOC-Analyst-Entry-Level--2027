# SOC Analyst Incident Response Portfolio (2027)

Welcome to my Security Operations Center (SOC) investigation portfolio. This repository documents hands-on threat triage, endpoint telemetry analysis, and incident response workflows conducted using enterprise simulation platforms like LetsDefend.

## Completed Investigations

| Incident ID | Alert Name | Severity | Verdict | Writeup Link |
| :--- | :--- | :--- | :--- | :--- |
| SOC143 | Password Stealer Detected | Medium | True Positive | [View Report](./SOC143%20-%20Password%20Stealer%20Detected) |
| SOC205 | Malicious Macro Execution | Medium | True Positive | [View Report](./SOC205-Malicious-Macro-Execution) |
| SOC325 | Unauthorized Cloud Region Access Attempt Detected | Low | True Positive | [View Report](./Lab%202) |
| SOC101 | Phishing Mail Detected | Medium | False Positive | [View Report](./SOC101-Phishing-Mail-Detected) |


---

## Core Competencies Demonstrated
- **Phishing & Email Security:** Ingress header inspection, SPF/DKIM verification, address spoofing identification, and mailbox administrative purge.
- **Endpoint Triage & Process Correlation:** Sysmon process-lineage analysis, parent-child inspection, command execution verification, and host isolation via EDR.
- **Network Traffic & SIEM Log Correlation:** Proxy logs, firewall state tables, C2 beaconing analysis, and outbound TCP telemetry.
- **Cloud Perimeter & Ingress Monitoring:** Unused/unsupported cloud region policy enforcement, geo-blocking, and brute-force triage.
- **Threat Intelligence & IoC Management:** Artifact enrichment via VirusTotal, AnyRun, and AbuseIPDB, along with perimeter blocklist deployment.
- **Framework Grounding:** End-to-end mapping across the MITRE ATT&CK enterprise matrix.

---

## Technical Summary of Investigations

### [SOC143 - Password Stealer Detected](./SOC143%20-%20Password%20Stealer%20Detected)
- **Event ID:** 90 | **Type:** Exchange Gateway | **Severity:** Medium
- **Target:** `ellie@letsdefend.io`
- **Attacker Mail Server IP:** `180.76.101.229` (Baidu Infrastructure)
- **Vector:** Spearphishing email spoofing `bill@microsoft.com` containing infostealer malware.
- **Analysis & Outcome:** Exchange gateway logged `Device Action: Allowed`. Endpoint telemetry and network logs confirmed zero outbound beaconing or malicious execution (`Not Opened`). Contained by purging the malicious payload from the recipient mailbox and blocklisting the rogue SMTP infrastructure.
- **Key MITRE ATT&CK:** T1566.001 (Spearphishing Attachment/Link), T1036.005 (Masquerading), T1555 (Credentials from Password Stores).

### [SOC205 - Malicious Macro Execution](./SOC205-Malicious-Macro-Execution)
- **Event ID:** 231 | **Host:** Jayne (`172.16.17.198`) | **Severity:** Medium
- **Artifact:** `edit1-invoice.docm` | **Identified C2:** `92.204.221.16:80`
- **Vector:** Malicious macro embedded inside a weaponized invoice document.
- **Analysis & Outcome:** Sysmon Event IDs 4688 and 4104 verified macro execution spawning `powershell.exe` to trigger remote script blocks. Proxy and firewall logs confirmed live outbound HTTP C2 traffic to `92.204.221.16:80`. Remediated by host network isolation via EDR, terminating spawned processes, file eradication, and perimeter egress blocking.
- **Key MITRE ATT&CK:** T1566.001 (Spearphishing Attachment), T1204.002 (User Execution), T1059.005 (VBA), T1059.001 (PowerShell), T1071.001 (Web Protocols).

### [SOC325 - Unauthorized Cloud Region Access Attempt Detected](./Lab%202)
- **Event ID:** 303 | **Host:** `52.15.206.21` (Ubuntu Linux) | **Severity:** Low
- **Attacker Source IP:** `134.209.145.73` | **Target User:** `test@letsdefend.io`
- **Vector:** Web application authentication request originating from an unsupported cloud region.
- **Analysis & Outcome:** Threat intel confirmed source IP reputation for brute-force scanning. The reverse proxy and firewall enforced `Device Action: Blocked` (`HTTP 403 Forbidden`). Because ingress controls rejected the request, scope remained unexpanded and host isolation was unnecessary.
- **Key MITRE ATT&CK:** T1535 (Unused/Unsupported Cloud Regions), T1078 (Valid Accounts), T1133 (External Remote Services).
