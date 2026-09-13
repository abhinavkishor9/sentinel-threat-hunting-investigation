# sentinel-threat-hunting-investigation
## Overview
Threat hunting is a proactive SOC activity in which an analyst searches security telemetry for suspicious behavior that may not have generated an alert.

Instead of waiting for Sentinel to raise an incident, the analyst starts with a hypothesis and uses KQL to test it.

For this project, the main hypothesis is:

A single source IP generating repeated authentication failures against multiple accounts may indicate password-spraying activity.

The investigation then asks:

Is the source generating failed authentication?
How many accounts are being targeted?
Are the failures concentrated in a short period?
Does the same source eventually authenticate successfully?
Does the combined evidence support a password-spraying hypothesis?
Is there enough evidence to confirm account compromise?

Rather than inventing production events, the project uses KQL's datatable() operator to create controlled authentication telemetry.

This allows us to demonstrate:

KQL investigation
filtering
aggregation
source-IP analysis
account targeting
password-spray detection
timeline reconstruction
detection engineering
Important distinction

The data is:

Controlled / synthetic

It is not:

Real production authentication telemetry

Therefore, the project can demonstrate that the detection logic works, but it must not claim that a real Microsoft Entra account was compromised.

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


A SOC analyst is investigating unusual authentication activity observed within a controlled Microsoft Sentinel environment. The activity involves a single source IP, `185.220.101.10`, generating multiple failed authentication attempts against several user accounts within a short timeframe.

The investigation begins with seven failed authentication attempts affecting four distinct accounts. The failures use result code `50126` and are associated with Microsoft Office. After the sequence of failures, the same source IP successfully authenticates as `user1@sentinellab.local`.

The analyst must determine whether this pattern is consistent with password-spraying behavior and whether the successful authentication requires further investigation. The exercise focuses on source-IP concentration, account targeting, event sequencing, and correlation between failed and successful authentication.

The authentication records are intentionally created using KQL `datatable()` because usable persistent `SigninLogs` telemetry is not available for the exercise. The scenario therefore demonstrates the investigation process and detection methodology without claiming a real production compromise.

The key evidence to investigate includes:

- `185.220.101.10` generating 7 failed authentication attempts.
- 4 distinct user accounts being targeted.
- Failure result code `50126`.
- Activity occurring approximately between 10:01 and 10:07 UTC.
- A successful authentication for `user1@sentinellab.local` from the same source at 10:08 UTC.
- A later successful authentication for the same user from `10.10.10.25`, with Hyderabad recorded as the location.

The expected outcome is an evidence-based SOC assessment of the authentication pattern, including whether it supports a possible password-spray hypothesis, what remains unconfirmed, and what additional telemetry would be required for further investigation.

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

