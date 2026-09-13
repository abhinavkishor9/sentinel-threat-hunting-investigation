# Investigation Timeline

## Overview

This timeline documents the authentication activity associated with the controlled investigation.

The primary source under investigation is:

`185.220.101.10`

The activity demonstrates repeated authentication failures against multiple accounts followed by a successful authentication from the same source.

The timestamps below are based on the controlled `datatable()` telemetry used in the lab.

---

## Chronological Timeline

### 10:01 UTC

```text
User: user1@sentinellab.local
Source IP: 185.220.101.10
Result: Failed
Result Type: 50126
Application: Microsoft Office
Reason: Invalid username or password
```

Initial authentication failure from the suspicious source.

---

### 10:02 UTC

```text
User: user1@sentinellab.local
Source IP: 185.220.101.10
Result: Failed
Result Type: 50126
Application: Microsoft Office
Reason: Invalid username or password
```

A second failure occurs against the same account and source.

---

### 10:03 UTC

```text
User: user2@sentinellab.local
Source IP: 185.220.101.10
Result: Failed
Result Type: 50126
Application: Microsoft Office
Reason: Invalid username or password
```

The source begins targeting a different account.

---

### 10:04 UTC

```text
User: user3@sentinellab.local
Source IP: 185.220.101.10
Result: Failed
Result Type: 50126
Application: Microsoft Office
Reason: Invalid username or password
```

A third distinct account is targeted.

---

### 10:05 UTC

```text
User: user4@sentinellab.local
Source IP: 185.220.101.10
Result: Failed
Result Type: 50126
Application: Microsoft Office
Reason: Invalid username or password
```

A fourth distinct account is targeted.

At this point, the source has targeted four accounts.

---

### 10:06 UTC

```text
User: user2@sentinellab.local
Source IP: 185.220.101.10
Result: Failed
Result Type: 50126
Application: Microsoft Office
Reason: Invalid username or password
```

The source returns to an account previously targeted.

---

### 10:07 UTC

```text
User: user3@sentinellab.local
Source IP: 185.220.101.10
Result: Failed
Result Type: 50126
Application: Microsoft Office
Reason: Invalid username or password
```

Another failure occurs against a previously targeted account.

The suspicious source has now generated:

```text
7 failed authentication attempts
4 distinct targeted accounts
```

---

### 10:08 UTC

```text
User: user1@sentinellab.local
Source IP: 185.220.101.10
Result: Success
Application: Microsoft Office
Location: Unknown
```

A successful authentication occurs from the same source IP that generated the previous failures.

This is the most important correlation point in the investigation.

The sequence is:

```text
7 Failed Attempts
        ↓
4 Targeted Accounts
        ↓
Same Source IP
        ↓
Successful Authentication
```

The activity is therefore assessed as suspicious and consistent with possible password spraying followed by successful authentication.

However, this does not independently establish that the account was compromised.

---

### 10:10 UTC

```text
User: user1@sentinellab.local
Source IP: 10.10.10.25
Result: Success
Application: Microsoft Office
Location: Hyderabad
```

A second successful authentication occurs for the same user from a different source IP.

This event provides additional context but does not independently prove compromise.

---

## Investigation Summary

The complete sequence is:

```text
10:01  user1  Failed
10:02  user1  Failed
10:03  user2  Failed
10:04  user3  Failed
10:05  user4  Failed
10:06  user2  Failed
10:07  user3  Failed
10:08  user1  Success
10:10  user1  Success from 10.10.10.25
```

The suspicious source generated seven failed authentication attempts against four distinct accounts within approximately seven minutes.

The same source then successfully authenticated as `user1`.

---

## Detection Correlation

The timeline supports the following behavioral pattern:

```text
Repeated Failures
        +
Multiple Targeted Accounts
        +
Common Source IP
        +
Short Timeframe
        +
Successful Authentication
        =
Possible Password Spraying
```

The detection threshold used in the lab was:

```kusto
| where TargetedAccounts >= 3
```

The suspicious source produced:

```text
TargetedAccounts = 4
```

Therefore, it exceeded the lab threshold.

---

## SOC Assessment

### Verdict

**SUSPICIOUS**

### Confidence

**Moderate**

### Password Spraying

**Possible and supported by the controlled evidence.**

### Account Compromise

**Not confirmed.**

### Production Incident

**Not claimed.**

---

## Evidence Gaps

The following evidence was not available in the controlled dataset:

- MFA result
- Conditional Access result
- Sign-in risk
- User risk
- Device information
- Endpoint telemetry
- Post-authentication activity
- Token or session information
- Additional identity-provider telemetry

These gaps prevent confirmation of account compromise.

---

## Final Timeline Assessment

The strongest evidence is not any individual failed authentication event.

The important finding is the sequence:

```text
One Source
    ↓
Seven Failures
    ↓
Four Targeted Accounts
    ↓
Short Timeframe
    ↓
Successful Authentication
```

This pattern warrants further investigation in a real SOC environment.

The appropriate conclusion is:

> The controlled authentication pattern is consistent with possible password spraying followed by successful authentication. Additional telemetry is required to determine whether the successful authentication represents account compromise.
