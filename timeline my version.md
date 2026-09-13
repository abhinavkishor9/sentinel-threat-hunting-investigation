# Investigation Timeline

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

