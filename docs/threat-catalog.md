# Threat Catalog

Complete list of threats detected by the Lambda THREAT_RULES engine.
Each rule maps a CloudTrail `eventName` to a severity level, description,
and remediation action.

---

## Detection Logic Flow

```
CloudTrail event arrives at Lambda
          │
          ▼
    eventName extracted
          │
          ├── ConsoleLogin? → special handler (Root vs NoMFA check)
          │
          ├── errorCode = AccessDenied? → recon counter check
          │
          └── everything else → THREAT_RULES dict lookup
                                      │
                                      ├── no match → skip, return
                                      │
                                      └── match found
                                                │
                                                ├── optional check fn?
                                                │   → evaluate condition
                                                │
                                                ├── severity scored
                                                │
                                                ├── remediation: auto?
                                                │   → execute boto3 fix
                                                │
                                                ├── log to DynamoDB
                                                │
                                                └── publish to SNS topic
```

---

## 🔴 CRITICAL Threats

---

### CT-001 — Root Account Login

| Field | Value |
|---|---|
| Event Source | `aws.signin` |
| Event Name | `ConsoleLogin` |
| Condition | `userIdentity.type == "Root"` |
| Severity | CRITICAL |
| Remediation | Alert only |
| GuardDuty Equivalent | `Policy:IAMUser/RootCredentialUsage` |

**Why it matters**

Root account has unrestricted access to every resource in the AWS account
with no IAM boundary. AWS best practice is to never use root for day-to-day
operations — any root login is immediately suspicious and warrants
investigation regardless of context.

**What Lambda does**

Cannot safely lock out root programmatically (would make account
inaccessible). Fires CRITICAL SNS alert immediately with actor IP
and timestamp for manual investigation.

---

### CT-002 — CloudTrail Logging Disabled

| Field | Value |
|---|---|
| Event Source | `aws.cloudtrail` |
| Event Name | `StopLogging` |
| Condition | None (any StopLogging triggers) |
| Severity | CRITICAL |
| Remediation | ✅ Auto — calls `start_logging()` |
| GuardDuty Equivalent | `Stealth:IAMUser/CloudTrailLoggingDisabled` |

**Why it matters**

Disabling CloudTrail is one of the first steps an attacker takes after
gaining access — it removes the audit trail of everything they do next.
Ironically, CloudTrail logs its own disabling before stopping, which
is how this detection works.

**What Lambda does**

Immediately calls `cloudtrail:StartLogging` to re-enable the trail.
Alert includes trail name and actor. Window of blind spot is typically
under 30 seconds (EventBridge → Lambda latency).

---

### CT-003 — CloudTrail Trail Deleted

| Field | Value |
|---|---|
| Event Source | `aws.cloudtrail` |
| Event Name | `DeleteTrail` |
| Condition | None |
| Severity | CRITICAL |
| Remediation | Alert only |
| GuardDuty Equivalent | `Stealth:IAMUser/CloudTrailLoggingDisabled` |

**Why it matters**

More severe than StopLogging — deleting the trail removes the logging
configuration entirely, not just pauses it. Recreating a trail requires
knowing the original S3 bucket, log group, and settings.

**What Lambda does**

Alert only — cannot safely recreate trail without knowing original
configuration. Email includes actor and timestamp for immediate
manual response.

---

### CT-004 — AdministratorAccess Attached to IAM User

| Field | Value |
|---|---|
| Event Source | `aws.iam` |
| Event Name | `AttachUserPolicy` |
| Condition | `requestParameters.policyArn` contains `AdministratorAccess` |
| Severity | CRITICAL |
| Remediation | ✅ Auto — calls `detach_user_policy()` |
| GuardDuty Equivalent | `PrivilegeEscalation:IAMUser/AdministrativePermissions` |

**Why it matters**

Attaching `AdministratorAccess` to a user grants full unrestricted
access to every AWS service — equivalent to root for most operations.
Classic privilege escalation pattern used by attackers who gain
limited initial access and then try to expand permissions.

**What Lambda does**

Extracts `userName` and `policyArn` from `requestParameters`.
Immediately calls `iam:DetachUserPolicy` to revoke the policy.
Alert includes which user was targeted.

---

## 🟠 HIGH Threats

---

### HT-001 — Console Login Without MFA

| Field | Value |
|---|---|
| Event Source | `aws.signin` |
| Event Name | `ConsoleLogin` |
| Condition | `additionalEventData.MFAUsed == "No"` AND type != Root |
| Severity | HIGH |
| Remediation | Alert only |
| GuardDuty Equivalent | `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` |

**Why it matters**

Console access without MFA means a stolen password alone is enough
for full account access. AWS strongly recommends MFA on all human IAM
users with console access.

**What Lambda does**

Cannot force MFA retroactively or terminate an active session via API.
Fires HIGH alert with username and source IP so the account can be
reviewed and MFA enforced manually.

---

### HT-002 — New IAM User Created

| Field | Value |
|---|---|
| Event Source | `aws.iam` |
| Event Name | `CreateUser` |
| Condition | None |
| Severity | HIGH |
| Remediation | Alert only |
| GuardDuty Equivalent | `Persistence:IAMUser/UserCreation` |

**Why it matters**

In a controlled AWS environment, new IAM user creation should be rare
and always expected. Unexpected user creation could indicate an attacker
establishing persistence — a backdoor account that survives even if
the original compromised credentials are rotated.

**What Lambda does**

Alert only. Fires HIGH SNS alert with the new username and actor
(who created it) for review.

---

### HT-003 — New IAM Access Key Created

| Field | Value |
|---|---|
| Event Source | `aws.iam` |
| Event Name | `CreateAccessKey` |
| Condition | None |
| Severity | HIGH |
| Remediation | ✅ Auto — calls `update_access_key(Status='Inactive')` |
| GuardDuty Equivalent | `Persistence:IAMUser/AccessKeyCreation` |

**Why it matters**

Programmatic access keys are long-lived credentials that work outside
the console, bypass MFA, and can be used from any IP. Attackers
create access keys immediately after gaining console access to
maintain persistence even if the password is changed.

**What Lambda does**

Extracts `accessKeyId` and `userName` from `responseElements`.
Calls `iam:UpdateAccessKey` to set status to `Inactive`.
Alert includes key ID for audit trail.

---

### HT-004 — S3 Bucket ACL Modified

| Field | Value |
|---|---|
| Event Source | `aws.s3` |
| Event Name | `PutBucketAcl` |
| Condition | None |
| Severity | HIGH |
| Remediation | Alert only |
| GuardDuty Equivalent | `Policy:S3/BucketAnonymousAccessGranted` |

**Why it matters**

Changing a bucket ACL to `public-read` or `public-read-write` exposes
all bucket contents to the internet. A common data exfiltration technique
— attacker makes bucket public, downloads data, then restores ACL to
avoid detection.

**What Lambda does**

Alert only with bucket name and actor. Manual review required to
determine if ACL change was intentional.

---

### HT-005 — S3 Bucket Policy Modified

| Field | Value |
|---|---|
| Event Source | `aws.s3` |
| Event Name | `PutBucketPolicy` |
| Condition | None |
| Severity | HIGH |
| Remediation | Alert only |
| GuardDuty Equivalent | `Policy:S3/BucketAnonymousAccessGranted` |

**Why it matters**

Bucket policies can grant access to external AWS accounts or make
data publicly accessible. More powerful than ACLs — a malicious bucket
policy can grant cross-account access that's harder to detect.

**What Lambda does**

Alert only with bucket name and actor for manual review.

---

## 🟡 MEDIUM Threats

---

### MT-001 — Secrets Manager Secret Accessed

| Field | Value |
|---|---|
| Event Source | `aws.secretsmanager` |
| Event Name | `GetSecretValue` |
| Condition | None |
| Severity | MEDIUM |
| Remediation | Alert only |
| GuardDuty Equivalent | `CredentialAccess:Secrets Manager/MaliciousIPCaller` |

**Why it matters**

Secrets Manager stores database passwords, API keys, and other
sensitive credentials. Unexpected `GetSecretValue` calls — especially
from unusual IAM users or at unusual times — indicate credential
harvesting.

**What Lambda does**

Alert only. Fires MEDIUM SNS alert with actor and timestamp.
Legitimate application access will fire this too — the alert is
for awareness and pattern monitoring.

---

### MT-002 — Security Group Opened to 0.0.0.0/0

| Field | Value |
|---|---|
| Event Source | `aws.ec2` |
| Event Name | `AuthorizeSecurityGroupIngress` |
| Condition | `requestParameters` contains `"0.0.0.0/0"` |
| Severity | MEDIUM |
| Remediation | Alert only |
| GuardDuty Equivalent | `Recon:EC2/PortProbeUnprotectedPort` |

**Why it matters**

Opening inbound rules to all IPs exposes EC2 instances to the
entire internet. Common mistake that becomes a security hole —
especially dangerous on ports 22 (SSH), 3389 (RDP), or database ports.

**What Lambda does**

Checks `requestParameters` for `0.0.0.0/0` before triggering.
Alert only with security group ID and port range.

---

### MT-003 — CloudTrail Configuration Modified

| Field | Value |
|---|---|
| Event Source | `aws.cloudtrail` |
| Event Name | `UpdateTrail` |
| Condition | None |
| Severity | MEDIUM |
| Remediation | Alert only |
| GuardDuty Equivalent | `Stealth:IAMUser/CloudTrailLoggingDisabled` |

**Why it matters**

Updating a trail can reduce logging coverage — for example, switching
from multi-region to single-region, disabling global service events,
or changing the S3 destination. A subtle way to reduce visibility
without fully disabling logging.

**What Lambda does**

Alert only with actor and trail name for review.

---

### MT-004 — Inline Policy Added to IAM Role

| Field | Value |
|---|---|
| Event Source | `aws.iam` |
| Event Name | `PutRolePolicy` |
| Condition | None |
| Severity | MEDIUM |
| Remediation | Alert only |
| GuardDuty Equivalent | `PrivilegeEscalation:IAMUser/RolePolicy` |

**Why it matters**

Inline policies are attached directly to a role and don't appear
in the managed policy list — making them harder to audit. Attackers
use inline policies to quietly expand permissions on existing roles
without creating new managed policies that might be monitored.

**What Lambda does**

Alert only with role name and actor.

---

### MT-005 — IAM Role Trust Policy Modified

| Field | Value |
|---|---|
| Event Source | `aws.iam` |
| Event Name | `UpdateAssumeRolePolicy` |
| Condition | None |
| Severity | MEDIUM |
| Remediation | Alert only |
| GuardDuty Equivalent | `PrivilegeEscalation:IAMUser/RolePolicy` |

**Why it matters**

A role's trust policy defines who can assume it. Modifying it to
allow an external account or an unexpected principal to assume the
role grants that entity all the role's permissions — a cross-account
privilege escalation technique.

**What Lambda does**

Alert only with role name and actor for review.

---

### MT-006 — IAM Access Key Deleted

| Field | Value |
|---|---|
| Event Source | `aws.iam` |
| Event Name | `DeleteAccessKey` |
| Condition | None |
| Severity | MEDIUM |
| Remediation | Alert only |
| GuardDuty Equivalent | N/A |

**Why it matters**

Key deletion is sometimes legitimate (rotation) but can also indicate
an attacker cleaning up evidence after exfiltrating data using a
compromised key. Worth monitoring in context alongside other events.

**What Lambda does**

Alert only with key ID and actor.

---

### MT-007 — Permission Recon Detected

| Field | Value |
|---|---|
| Event Source | Any |
| Event Name | Any with `errorCode: AccessDenied` |
| Condition | 5+ AccessDenied from same actor in 5 minutes |
| Severity | MEDIUM |
| Remediation | Alert only |
| GuardDuty Equivalent | `Recon:IAMUser/UserPermissions` |

**Why it matters**

Attackers with limited initial access probe for what they CAN do
by calling APIs and observing which ones return `AccessDenied`.
This enumeration pattern produces bursts of denied calls in a
short window — a behavioral signal not visible from any single event.

**How detection works**

Lambda maintains a per-actor counter in the DynamoDB `recon-counter`
table with a 5-minute sliding window. Each `AccessDenied` increments
the counter. At 5 hits the MEDIUM alert fires and the counter resets.
This is the only stateful detection in the system — all others are
stateless per-event matches.

**What Lambda does**

Alert with actor name, hit count, and time window. Counter resets
after alert to avoid repeated firing for the same recon session.

---

## Threat Coverage vs GuardDuty

| GuardDuty Finding Type | Covered Here | Method |
|---|---|---|
| `Policy:IAMUser/RootCredentialUsage` | ✅ | CT-001 |
| `Stealth:IAMUser/CloudTrailLoggingDisabled` | ✅ | CT-002, CT-003, MT-003 |
| `PrivilegeEscalation:IAMUser/AdministrativePermissions` | ✅ | CT-004 |
| `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` | ✅ | HT-001 |
| `Persistence:IAMUser/UserCreation` | ✅ | HT-002 |
| `Persistence:IAMUser/AccessKeyCreation` | ✅ | HT-003 |
| `Policy:S3/BucketAnonymousAccessGranted` | ✅ | HT-004, HT-005 |
| `CredentialAccess:Secrets Manager` | ✅ | MT-001 |
| `Recon:EC2/PortProbeUnprotectedPort` | ⚠️ Partial | MT-002 (SG rule only) |
| `Recon:IAMUser/UserPermissions` | ✅ | MT-007 |
| `PrivilegeEscalation:IAMUser/RolePolicy` | ✅ | MT-004, MT-005 |
| Network-based findings (crypto mining, C2 traffic) | ❌ | Needs VPC Flow Logs + ML |
| Behavioral anomaly detection | ❌ | Needs ML baseline |
| Threat intelligence IP feeds | ❌ | Needs GuardDuty data |

---

## Adding New Threat Rules

To add a new rule, append to `THREAT_RULES` in `lambda_function.py`:

```python
"EventNameHere": {
    "severity"    : "HIGH",                    # CRITICAL / HIGH / MEDIUM
    "title"       : "Short Human Label",
    "description" : "What happened and why it matters.",
    "check"       : lambda d: "condition" in str(d),  # optional
    "remediation" : "alert_only"               # auto / alert_only
},
```

If `remediation` is `"auto"`, add a corresponding function to
`REMEDIATION_MAP` in the Lambda code.
