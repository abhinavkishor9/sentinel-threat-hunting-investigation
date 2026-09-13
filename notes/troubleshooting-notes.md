# Troubleshooting Notes — Sentinel Threat Hunting Investigation

## 1. Persistent SigninLogs Telemetry Was Not Available

### Issue

The investigation initially expected to work with persistent Microsoft Entra authentication telemetry such as `SigninLogs`.

However, usable event-level `SigninLogs` telemetry was not available for the investigation.

Previous testing showed that expected fields such as `TimeGenerated` or `Timestamp` were not available in the required form for the intended investigation query.

### Impact

Using a production-style query against unavailable telemetry would either produce errors or provide no useful investigation evidence.

### Resolution

Instead of inventing production events, the investigation uses controlled KQL `datatable()` telemetry.

This allows the investigation logic to be demonstrated without claiming that the events came from a live production environment.

---

## 2. Why `datatable()` Was Used

### Problem

The investigation required authentication events with:

- `TimeGenerated`
- `UserPrincipalName`
- `IPAddress`
- `ResultType`
- `ResultDescription`
- `AppDisplayName`
- `Location`

These fields were needed to demonstrate:

- Authentication failures
- Source IP analysis
- Account targeting
- Successful authentication
- Timeline reconstruction

### Resolution

A controlled dataset was created using KQL `datatable()`:

```kusto
datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    ResultType: int,
    ResultDescription: string,
    AppDisplayName: string,
    Location: string
)
```

### Important Limitation

The resulting events are controlled lab telemetry.

They must not be represented as real Microsoft Entra authentication events.

---

## 3. `TargetedAccounts` Error

### Issue

The following condition can produce an error if `TargetedAccounts` has not yet been created:

```kusto
| where TargetedAccounts >= 3
```

For example, this is incomplete:

```kusto
| where ResultType != 0
| where TargetedAccounts >= 3
```

`TargetedAccounts` does not exist at that stage of the query.

### Cause

`TargetedAccounts` is an alias created by `summarize`.

It must first be defined:

```kusto
| summarize TargetedAccounts = dcount(UserPrincipalName) by IPAddress
```

Only after that can it be filtered.

### Correct Query

```kusto
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    TargetedAccounts = dcount(UserPrincipalName)
    by IPAddress
| where TargetedAccounts >= 3
```

### Expected Result

```text
IPAddress          FailedAttempts    TargetedAccounts
185.220.101.10     7                 4
```

This was the working detection logic demonstrated in the investigation screenshots.

---

## 4. Pipeline Fragment Error

### Issue

A KQL pipeline fragment such as:

```kusto
| where TargetedAccounts >= 3
```

cannot be executed as a complete standalone query.

### Cause

KQL requires a table expression before the pipe operator.

The pipe modifies the result of the expression immediately before it.

### Incorrect

```kusto
| where TargetedAccounts >= 3
```

### Correct

```kusto
datatable(
    IPAddress: string,
    TargetedAccounts: int
)
[
    "185.220.101.10", 4
]
| where TargetedAccounts >= 3
```

For the actual investigation, the aggregation must occur before the filter:

```kusto
datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    ResultType: int
)
[
    datetime(2026-09-11T10:01:00Z), "user1@sentinellab.local", "185.220.101.10", 50126
]
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    TargetedAccounts = dcount(UserPrincipalName)
    by IPAddress
| where TargetedAccounts >= 3
```

---

## 5. Difference Between `count()` and `dcount()`

The investigation uses two different aggregation concepts.

### `count()`

Counts the total number of matching events.

```kusto
FailedAttempts = count()
```

In this investigation:

```text
FailedAttempts = 7
```

### `dcount()`

Counts distinct values.

```kusto
TargetedAccounts = dcount(UserPrincipalName)
```

In this investigation:

```text
TargetedAccounts = 4
```

This distinction is important because seven failed events do not necessarily mean seven targeted accounts.

The controlled dataset contains seven failures against four distinct accounts.

---

## 6. Why `make_set()` Was Used

The investigation also used:

```kusto
Accounts = make_set(UserPrincipalName, 20)
```

This creates a collection of distinct account names associated with the source IP.

The result demonstrated that the suspicious source targeted:

```text
user1@sentinellab.local
user2@sentinellab.local
user3@sentinellab.local
user4@sentinellab.local
```

`make_set()` is useful for analyst visibility, while `dcount()` is useful for calculating the number of distinct accounts.

---

## 7. Difference Between `ResultType == 0` and `ResultType != 0`

Successful authentication was identified using:

```kusto
| where ResultType == 0
```

Failed authentication was identified using:

```kusto
| where ResultType != 0
```

This allowed the investigation to separate successful and failed authentication events.

The controlled dataset contained:

```text
7 failed events
2 successful events
```

---

## 8. Successful Authentication Does Not Equal Compromise

### Potential Misinterpretation

A successful login following several failed attempts may appear to prove that the password spray succeeded.

However, the available controlled telemetry does not establish how the successful authentication occurred.

### Correct Interpretation

The evidence supports:

```text
Possible password spraying
followed by
successful authentication
```

It does not independently prove:

```text
Confirmed account compromise
```

Additional evidence such as MFA, Conditional Access, device information, sign-in risk, endpoint telemetry, and post-authentication activity would be required.

---

## 9. Detection Logic vs Production Analytics Rule

The project demonstrates detection logic.

It does not claim that a production Sentinel Analytics Rule generated an alert from these controlled events.

The detection design is:

```text
Failed Authentication
        +
Same Source IP
        +
3+ Targeted Accounts
        =
Possible Password Spraying
```

A production implementation would require:

- Persistent authentication telemetry
- Appropriate entity mapping
- Threshold tuning
- Scheduling configuration
- Alert suppression or grouping considerations
- False-positive tuning
- Incident creation configuration

---

## 10. Why the Threshold Is 3 Accounts

The lab uses:

```kusto
| where TargetedAccounts >= 3
```

This is a demonstration threshold.

It is not intended to represent a universal enterprise detection threshold.

Production environments may require different thresholds depending on:

- Organization size
- NAT architecture
- Service accounts
- VPN infrastructure
- Known scanners
- Identity provider behavior
- Existing authentication controls
- Normal authentication volume

The threshold should therefore be tuned against baseline behavior.

---

## 11. Timeline Validation

The suspicious IP timeline was checked against the controlled dataset.

The observed sequence was:

```text
10:01  user1  Failed
10:02  user1  Failed
10:03  user2  Failed
10:04  user3  Failed
10:05  user4  Failed
10:06  user2  Failed
10:07  user3  Failed
10:08  user1  Success
```

This confirms that the successful authentication occurred immediately after the sequence of failed attempts from the same source.

---

## 12. Evidence Handling

The investigation follows an evidence-based approach.

The following distinctions are maintained:

- Observed
- Supported
- Possible
- Confirmed
- Unknown

The controlled dataset confirms the authentication events because they were explicitly created for the lab.

The malicious nature of the activity remains an assessment rather than a proven fact.

The project therefore avoids claiming:

- Confirmed attacker
- Confirmed credential theft
- Confirmed account compromise
- Confirmed production incident

---

## Final Troubleshooting Assessment

The main technical issue encountered during the investigation was not with the detection concept itself, but with query structure and telemetry availability.

The final working pattern is:

```kusto
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    TargetedAccounts = dcount(UserPrincipalName)
    by IPAddress
| where TargetedAccounts >= 3
```

The important KQL principle is:

> Create an aggregation field before attempting to filter on that field.

This prevents the `TargetedAccounts` unknown-column error encountered during the lab.
