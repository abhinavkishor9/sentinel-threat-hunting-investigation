# Microsoft Sentinel Threat Hunting Investigation

## Overview

This project documents a Microsoft Sentinel threat-hunting investigation focused on suspicious authentication activity and possible password spraying.

The investigation uses controlled authentication telemetry created with the KQL `datatable()` operator. This approach was used because persistent event-level `SigninLogs` telemetry was not available in a usable form for the exercise.

The investigation follows a SOC workflow:

```text
Controlled Telemetry
        ↓
Threat Hunting
        ↓
Authentication Analysis
        ↓
Source IP Correlation
        ↓
Password-Spray Detection
        ↓
Timeline Reconstruction
        ↓
SOC Assessment
```

The purpose of the project is to demonstrate practical KQL investigation and detection-engineering skills without presenting synthetic data as real production telemetry.

---

## Project Scenario

The controlled dataset represents authentication activity involving several user accounts.

A single source IP generates repeated authentication failures against multiple accounts and later successfully authenticates as one of the targeted users.

The investigation hypothesis is:

> A single source IP generating repeated authentication failures against multiple accounts may indicate password-spraying activity.

The investigation evaluates whether the observed authentication pattern supports this hypothesis.

---

## Controlled Dataset

| Attribute | Value |
|---|---|
| Suspicious IP | `185.220.101.10` |
| Failed attempts | 7 |
| Targeted accounts | 4 |
| Successful login from same IP | 1 |
| Application | Microsoft Office |
| Failure code | `50126` |
| Failure reason | Invalid username or password |
| Additional successful IP | `10.10.10.25` |
| Additional login location | Hyderabad |

The suspicious sequence occurs between 10:01 and 10:08 UTC.

---

## Important Telemetry Limitation

The authentication events used in this investigation are controlled KQL `datatable()` records.

They are not live Microsoft Entra ID production `SigninLogs`.

This distinction is important because the project demonstrates detection logic and investigation methodology rather than a real-world account compromise.

The investigation therefore does not claim that an actual account was compromised.

---

## Threat Hunting Concept

Threat hunting is a proactive SOC activity where an analyst searches security telemetry for suspicious behavior that may not have generated an alert.

Instead of waiting for an incident, the analyst begins with a hypothesis and uses KQL to test it.

For this investigation, the hunting process is:

```text
Hypothesis
    ↓
KQL Query
    ↓
Authentication Evidence
    ↓
Source IP Analysis
    ↓
Account Targeting Analysis
    ↓
Timeline Correlation
    ↓
SOC Assessment
```

---

## Investigation Objectives

The project demonstrates how to:

- Create controlled authentication telemetry using `datatable()`
- Perform KQL-based threat hunting
- Identify failed authentication attempts
- Identify multiple accounts targeted by one source IP
- Detect possible password-spraying behavior
- Correlate authentication failures with a later success
- Reconstruct an authentication timeline
- Develop detection logic
- Evaluate false-positive possibilities
- Distinguish suspicious activity from confirmed compromise
- Document an investigation for a SOC portfolio

---

## Environment

### Platform

Microsoft Sentinel

### Query Language

Kusto Query Language (KQL)

### Investigation Type

Authentication Threat Hunting

### Data Technique

KQL `datatable()`

### Primary Hypothesis

Possible password spraying followed by successful authentication

---

## Investigation Workflow

### 1. Create Controlled Telemetry

Authentication events are created directly in KQL using `datatable()`.

### 2. Examine Raw Events

The events are ordered chronologically to establish the baseline evidence.

### 3. Identify Failed Authentication

Authentication failures are filtered using the result type.

### 4. Group Failures by Source IP

Failed authentication events are summarized by source IP.

The investigation calculates:

- Total failed attempts
- Number of unique targeted accounts
- Targeted account list

### 5. Apply Password-Spray Threshold

A source is considered suspicious when it targets at least three distinct accounts.

### 6. Investigate the Suspicious Source

The complete event sequence associated with `185.220.101.10` is reviewed.

### 7. Correlate Successful Authentication

The investigation checks whether the suspicious source later generated a successful authentication.

### 8. Reconstruct the Timeline

The events are placed into chronological order to determine whether the failures and success form a meaningful sequence.

### 9. Assess the Evidence

The complete pattern is assessed rather than relying on a single authentication event.

---

## Key Finding

The controlled dataset contains:

- 7 failed authentication attempts
- 4 distinct targeted accounts
- 1 suspicious source IP
- Activity concentrated within approximately seven minutes
- 1 successful authentication from the same suspicious source

The source IP `185.220.101.10` therefore satisfies the project's password-spray detection threshold.

---

## Detection Logic

The core detection logic is:

```kusto
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    TargetedAccounts = dcount(UserPrincipalName)
    by IPAddress
| where TargetedAccounts >= 3
```

The final condition:

```kusto
| where TargetedAccounts >= 3
```

is applied only after `TargetedAccounts` has been created by the `summarize` statement.

This is important because `TargetedAccounts` does not exist in the original event stream. It is a calculated column produced by `summarize`.

---

## Detection Interpretation

```text
Failed authentication
        +
Same source IP
        +
Three or more targeted accounts
        =
Possible password spraying
```

For the controlled dataset:

```text
Source IP:          185.220.101.10
Failed attempts:    7
Targeted accounts:  4
```

The source therefore meets the defined threshold.

---

## Correlated Authentication

The investigation identified a successful authentication from the same source after the failed attempts.

```text
10:01 UTC  user1  Failed
10:02 UTC  user1  Failed
10:03 UTC  user2  Failed
10:04 UTC  user3  Failed
10:05 UTC  user4  Failed
10:06 UTC  user2  Failed
10:07 UTC  user3  Failed
10:08 UTC  user1  Success
```

This increases the investigation priority because the same source that generated the multi-account failures subsequently authenticated successfully.

---

## False-Positive Considerations

Possible legitimate explanations include:

- Repeated incorrect password entry
- Shared corporate NAT address
- Misconfigured application
- Automated service using outdated credentials
- Authentication testing
- Legitimate account recovery activity

The strongest suspicious indicator is the combination of:

```text
Multiple accounts
+
Common source
+
Short timeframe
+
Subsequent successful authentication
```

---

## SOC Assessment

### Verdict

**SUSPICIOUS**

### Confidence

**Moderate**

### Password Spraying

**Possible / supported by controlled evidence**

### Account Compromise

**Not confirmed**

### Production Incident

**Not claimed**

The correct assessment is:

> The observed controlled authentication pattern is consistent with possible password spraying followed by successful authentication. Additional telemetry is required to determine whether the successful authentication represents account compromise.

---

## Proposed Detection

### Rule Name

`Possible Password Spray - Multiple Accounts`

### Severity

`Medium`

### Threshold

Three or more targeted accounts from the same source IP.

### Required Production Telemetry

Persistent authentication telemetry such as Microsoft Entra `SigninLogs`.

### Entity Candidates

- IP address
- User account

### Recommended SOC Investigation

```text
Investigate source IP
        ↓
Review targeted accounts
        ↓
Check successful authentication
        ↓
Review MFA activity
        ↓
Review Conditional Access results
        ↓
Review device activity
        ↓
Review post-authentication activity
        ↓
Determine whether compromise occurred
```

---

## Limitations

This project has several limitations:

1. The authentication data is synthetic and controlled.
2. The project does not use live production `SigninLogs`.
3. The successful authentication cannot be treated as proof of compromise.
4. IP reputation was not independently validated.
5. MFA and Conditional Access telemetry is not available in the controlled dataset.
6. Device and post-authentication activity is not available.
7. The detection threshold is a demonstration threshold and would require tuning for a production environment.

---


## Skills Demonstrated

- Microsoft Sentinel
- Kusto Query Language
- Threat Hunting
- Authentication Analysis
- Password-Spray Detection
- Source IP Analysis
- Event Correlation
- Timeline Reconstruction
- Detection Engineering
- False-Positive Analysis
- SOC Investigation
- Evidence-Based Assessment

---

## Investigation Principle

> Follow the evidence, not the assumption.

The project intentionally distinguishes between:

- Observed evidence
- Suspicious behavior
- Detection logic
- Investigation hypothesis
- Confirmed compromise

This prevents synthetic laboratory telemetry from being presented as a real production incident.
