# Investigation Notes — Sentinel Threat Hunting

## Investigation Overview

This investigation examines controlled authentication telemetry in Microsoft Sentinel to determine whether a source IP demonstrates behavior consistent with password spraying.

The investigation was designed around the following threat-hunting hypothesis:

> A single source IP generating repeated authentication failures against multiple accounts may indicate password-spraying activity.

The investigation does not rely on a pre-existing Sentinel alert. Instead, the analyst starts with the hypothesis and uses KQL to progressively investigate the available telemetry.

The authentication data used in this lab was created using KQL `datatable()` because persistent event-level `SigninLogs` telemetry was not available in a usable form.

---

## Hypothesis

The primary hypothesis was:

> A single source IP is repeatedly failing authentication against multiple accounts and may eventually authenticate successfully using a valid credential.

The investigation therefore focused on:

- Failed authentication attempts
- Source IP concentration
- Number of targeted accounts
- Activity timeframe
- Successful authentication from the suspicious source
- Whether the combined evidence supports a password-spraying hypothesis

---

## Evidence Source

The investigation uses controlled KQL telemetry containing:

```text
TimeGenerated
UserPrincipalName
IPAddress
ResultType
ResultDescription
AppDisplayName
Location
```

The primary suspicious source is:

`185.220.101.10`

The failure code observed in the dataset is:

`50126`

The failure description is:

`Invalid username or password`

The application is:

`Microsoft Office`

---

## Investigation Phase 1 — Review Authentication Events

The initial query displayed the authentication records in chronological order.

The purpose of this step was to establish the raw evidence before applying detection logic.

The dataset contained:

- Failed authentication events from `185.220.101.10`
- A successful authentication from the same IP
- A separate successful authentication from `10.10.10.25`

This initial review established that the dataset contained both failed and successful authentication activity.

---

## Investigation Phase 2 — Identify Authentication Failures

Failed authentication events were isolated using:

```kusto
| where ResultType != 0
```

The controlled dataset produced:

```text
7 failed authentication attempts
```

The failures were associated with:

```text
185.220.101.10
```

and involved multiple user accounts.

This confirmed that the source was not associated with only one isolated authentication failure.

---

## Investigation Phase 3 — Identify Multiple Targeted Accounts

The next step grouped failed authentication events by source IP.

The investigation used:

```kusto
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    TargetedAccounts = dcount(UserPrincipalName),
    Accounts = make_set(UserPrincipalName, 20)
    by IPAddress
| order by TargetedAccounts desc
```

The result was:

```text
IPAddress          FailedAttempts    TargetedAccounts
185.220.101.10     7                 4
```

The four targeted accounts were:

```text
user1@sentinellab.local
user2@sentinellab.local
user3@sentinellab.local
user4@sentinellab.local
```

This was the first strong behavioral indicator of possible password spraying.

A traditional brute-force attempt commonly focuses on one account, whereas password spraying attempts to use credentials against multiple accounts.

The controlled dataset therefore demonstrated a pattern worth investigating further.

---

## Investigation Phase 4 — Apply the Detection Threshold

The investigation then applied the threshold:

```kusto
| where TargetedAccounts >= 3
```

The important point is that `TargetedAccounts` is created by the preceding `summarize` statement.

The complete logic is:

```kusto
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    TargetedAccounts = dcount(UserPrincipalName)
    by IPAddress
| where TargetedAccounts >= 3
```

The suspicious source had:

```text
TargetedAccounts = 4
```

Therefore, it met the lab threshold.

### Assessment

**Possible password spraying**

This is a detection assessment rather than proof of malicious activity.

---

## Investigation Phase 5 — Investigate the Suspicious Source

The source IP was then investigated independently:

```text
185.220.101.10
```

The events associated with this source showed:

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

The activity occurred over approximately seven minutes.

The important characteristic is that the source moved across multiple accounts rather than repeatedly targeting only one account.

---

## Investigation Phase 6 — Correlate Successful Authentication

Successful authentication events were identified using:

```kusto
| where ResultType == 0
```

The controlled dataset contained:

```text
10:08 UTC
user1@sentinellab.local
185.220.101.10
Microsoft Office
Success
```

and:

```text
10:10 UTC
user1@sentinellab.local
10.10.10.25
Microsoft Office
Hyderabad
Success
```

The 10:08 authentication is particularly relevant because it originated from the same IP that generated the previous failed authentication activity.

This creates the following evidence chain:

```text
185.220.101.10
        ↓
7 failed authentication attempts
        ↓
4 distinct targeted accounts
        ↓
Short activity window
        ↓
Successful authentication
        ↓
user1 authenticated from the same source
```

This increases the priority of the investigation.

However, it does not independently establish that the account was compromised.

---

## Investigation Phase 7 — Behavioral Assessment

The evidence supports several observations.

### Observation 1 — Repeated Failures

The source generated seven failed authentication events.

### Observation 2 — Multiple Accounts

The source targeted four distinct accounts.

### Observation 3 — Short Timeframe

The failures occurred between approximately 10:01 and 10:07 UTC.

### Observation 4 — Same-Source Success

The source successfully authenticated as `user1` at 10:08 UTC.

### Observation 5 — Additional Successful Login

The same user later authenticated successfully from `10.10.10.25`, with Hyderabad recorded as the location.

---

## Detection Logic

The final detection logic is:

```kusto
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    TargetedAccounts = dcount(UserPrincipalName)
    by IPAddress
| where TargetedAccounts >= 3
```

The logic can be represented as:

```text
Failed Authentication
        +
Common Source
        +
3 or More Accounts
        =
Possible Password Spraying
```

The successful authentication can then be investigated separately to determine whether the activity represents a potential compromise.

---

## False-Positive Analysis

The behavior should not automatically be classified as malicious.

Potential legitimate explanations include:

- A user repeatedly entering an incorrect password
- A corporate NAT address shared by multiple users
- A misconfigured application
- An automated service using outdated credentials
- Authentication testing
- Account recovery activity

The strongest investigative signal is the combination of:

```text
Multiple Accounts
+
Common Source
+
Short Timeframe
+
Subsequent Successful Authentication
```

This combination justifies additional investigation.

---

## Evidence Assessment

### Confirmed

The following are confirmed within the controlled dataset:

- Seven failed authentication events
- Four distinct targeted accounts
- Source IP `185.220.101.10`
- Failure code `50126`
- Successful authentication from the same IP
- Additional successful authentication from `10.10.10.25`

### Supported

The following assessment is supported:

**Possible password spraying**

### Not Confirmed

The following cannot be confirmed from the available telemetry:

- Account compromise
- Credential theft
- Malicious intent
- Production security incident

This distinction is important for accurate SOC reporting.

---

## Recommended Next Investigation Steps

If this investigation were performed against live authentication telemetry, the next steps would include:

1. Review MFA results
2. Review Conditional Access decisions
3. Review sign-in risk
4. Review user risk
5. Identify the device used during the successful authentication
6. Review the user's subsequent activity
7. Search for additional activity from `185.220.101.10`
8. Determine whether other accounts were targeted
9. Check endpoint telemetry for suspicious activity
10. Escalate or contain the account if additional evidence supports compromise

---

## Final Assessment

### Verdict

**SUSPICIOUS**

### Confidence

**Moderate**

### Assessment

The controlled authentication pattern is consistent with possible password spraying followed by successful authentication.

The available telemetry is insufficient to confirm account compromise.

The correct SOC conclusion is:

> The observed controlled authentication pattern is consistent with possible password spraying followed by successful authentication. Additional authentication, MFA, Conditional Access, device, and endpoint telemetry would be required to determine whether the successful authentication represents account compromise.
