# SOC Analyst Incident Response Portfolio (2027)

Welcome to my Security Operations Center (SOC) investigation portfolio. This repository documents hands-on threat triage, endpoint telemetry analysis, and incident response workflows conducted using enterprise simulation platforms like LetsDefend.

## Completed Investigations

| Incident ID | Alert Name | Severity | Verdict | Writeup Link |
| :--- | :--- | :--- | :--- | :--- |
| SOC205 | Malicious Macro Execution | Medium | True Positive | [View Report](./SOC205-Malicious-Macro-Execution) |
| SOC325 | Unauthorized Cloud Region Access Attempt Detected | Low | True Positive | [View Report](./Lab%202) |

## Core Competencies Demonstrated
- Endpoint Triage & Process Correlation (Sysmon, EDR)
- Network Log Analysis (Proxy, Firewall)
- Threat Intelligence Verification & IoC Identification
- MITRE ATT&CK Framework Mapping


# LetsDefend - SOC325: Unauthorized Cloud Region Access Attempt Detected

## Alert Overview
- **Event ID:** 303
- **Rule Name:** SOC325 - Unauthorized Cloud Region Access Attempt Detected
- **Date/Time:** 2024-09-24 08:21:15 (+03:00)
- **Severity:** Low
- **Category:** Web Attack
- **Target OS:** Linux (Ubuntu 20.04.02)
- **Verdict:** True Positive

---

## Network & Threat Indicators (IOCs)
- **Source IP (Attacker):** `134.209.145.73`
- **Destination IP (Target Host):** `52.15.206.21`
- **Target User Account:** `test@letsdefend.io`
- **HTTP Request Method:** `POST /accounts/login HTTP/1.1`
- **HTTP Response Status:** `403 Forbidden`
- **Trigger Reason:** Access attempts generated from an unauthorized/unsupported cloud region in a short duration.

---

## MITRE ATT&CK Mapping
- **Tactic:** Defense Evasion / Initial Access
- **Technique:** Unused/Unsupported Cloud Regions (T1535)
- **Associated IDs:** T1586, T1078, T1133, T1535

---

## Investigation Details & Playbook Breakdown

### 1. Endpoint Identification
- Searched Destination IP `52.15.206.21` under **Endpoint Security**.
- Identified host operating system as **Linux** (`Ubuntu 20.04.02`).

### 2. Threat Intelligence & Reputation Check
- Querying the source IP `134.209.145.73` across VirusTotal and AbuseIPDB confirmed reports for SSH brute force, web attacks, and scanning activity.
- The traffic was originating from an untrusted geo-region breaching organization baseline policy.

### 3. Scope Assessment
- Queried Log Management for Source IP `134.209.145.73`.
- The attacker solely targeted `52.15.206.21`; no multi-host scanning or lateral movement was identified.
- **Scope Expanded:** No.

### 4. Containment Decision (Host Isolation)
- Evaluated firewall and reverse-proxy actions.
- The request resulted in **Device Action: Blocked** (`HTTP 403`).
- Because the malicious payload was rejected at the perimeter and the host was not breached, host isolation was unnecessary.
- **Isolated:** No.

---

## Conclusion & Recommendations
- **Classification:** True Positive (Malicious Intent).
- **Remediation:** 
  - Ensure IP `134.209.145.73` is placed on the network perimeter blocklist.
  - Maintain Geo-blocking and Cloud Guardrails for non-operational cloud zones.
  - Continue monitoring authentication logs on endpoint `52.15.206.21` for credential brute-force indicators.
