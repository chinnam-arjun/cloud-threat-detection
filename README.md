# Cloud Threat Detection & Automated Incident Response

An event-driven cloud security monitoring system built on AWS that detects **15+ threat patterns** across IAM, CloudTrail, S3, and EC2 — with automated incident response, severity-tiered alerting, DynamoDB audit logging, and a real-time CloudWatch dashboard.

Built entirely within the **AWS free tier** without GuardDuty, Security Hub, or Athena.

---

## Why No GuardDuty?

The textbook AWS security architecture looks like this:

```
CloudTrail → GuardDuty → Security Hub → EventBridge → Lambda → SNS
```

Clean. Powerful. Enterprise-grade. Also **$50–200+/month**.

As an intern building on a personal AWS account, that wasn't an option. So every managed service was replaced with a free-tier equivalent:

| Component    | Production Standard  | This Project             | Why Replaced          |
|--------------|----------------------|--------------------------|-----------------------|
| Detection    | GuardDuty (ML)       | Lambda THREAT_RULES      | $50–200/month         |
| Log Analysis | Athena (SQL on S3)   | CloudWatch Logs Insights | Pay per query         |
| Dashboard    | Security Hub         | CloudWatch Dashboard     | Additional cost       |
| Remediation  | Needs extra setup    | Built-in ✅              | —                     |
| Cost         | $50–200+/month       | **$0** ✅               | —                     |

> GuardDuty's real advantage is ML behavioral baselines and network-level visibility (VPC Flow Logs, DNS). For IAM and API-level threats, a well-written rule engine matches it — and forces deeper understanding of every detection layer.

---

## Architecture

```
  AWS Account Activity
  (IAM, S3, EC2, Console logins, Secrets...)
              │
              ▼
  ┌───────────────────────┐       ┌──────────────────────────────┐
  │       CloudTrail      │──────▶│          S3 Bucket           │
  │                       │       │  (log archive, SSE-S3 enc)   │
  │  Management events    │       └──────────────────────────────┘
  │  Multi-region: ON     │
  │  Global svc events: ON│
  └───────────┬───────────┘
              │ streams to
              ▼
  ┌───────────────────────┐
  │    CloudWatch Logs    │◀── Lambda execution logs
  │                       │
  │  CloudTrail-Logs      │
  │  /aws/lambda/         │
  │  threat-detection-    │
  │  engine               │
  └───────────┬───────────┘
              │
              ▼
  ┌───────────────────────┐
  │      EventBridge      │
  │     (ap-south-2)      │
  │                       │
  │  Single broad rule    │
  │  catches ALL events   │
  │  including IAM        │
  │  (works because trail │
  │  is multi-region +    │
  │  global svc events)   │
  └───────────┬───────────┘
              │ triggers
              ▼
  ┌───────────────────────────────────────┐
  │       Lambda — Detection Brain        │
  │       threat-detection-engine         │
  │                                       │
  │  ┌─────────────────────────────────┐  │
  │  │       THREAT_RULES engine       │  │
  │  │                                 │  │
  │  │  parse CloudTrail event         │  │
  │  │  match against 15 threat rules  │  │
  │  │  optional condition check       │  │
  │  │  score severity                 │  │
  │  │  check recon counter (DynamoDB) │  │
  │  └─────────────────────────────────┘  │
  │                                       │
  │  ┌─────────────────────────────────┐  │
  │  │       Remediation Engine        │  │
  │  │                                 │  │
  │  │  start_logging()                │  │
  │  │  detach_user_policy()           │  │
  │  │  update_access_key(Inactive)    │  │
  │  └─────────────────────────────────┘  │
  └──────┬──────────────────┬─────────────┘
         │                  │
         ▼                  ▼
  ┌─────────────┐   ┌───────────────────────┐
  │  SNS Topics │   │       DynamoDB        │
  │             │   │                       │
  │  critical   │   │  incident-log         │
  │  high       │   │  recon-counter        │
  │  medium     │   │                       │
  └──────┬──────┘   └───────────────────────┘
         │
         ▼
  ┌──────────────────────────────────────────┐
  │          CloudWatch Dashboard            │
  │                                          │
  │  Threat Detections  │ Errors │ Duration  │
  │  ─────────────────────────────────────── │
  │  Alerts by Severity (bar)                │
  │  ─────────────────────────────────────── │
  │  Recent Security Events    │ Threats     │
  │  ─────────────────────────────────────── │
  │  AccessDenied Recon Activity (line)      │
  └──────────────────────────────────────────┘
         │
         ▼
  ┌─────────────────┐
  │   Your Email    │
  │                 │
  │  🚨 [CRITICAL]  │
  │  🟠 [HIGH]      │
  │  🟡 [MEDIUM]    │
  └─────────────────┘

  Cost: $0 (fully within AWS free tier)
```

---

## Services Used

| Service       | Purpose                                | Free Tier          |
|---------------|----------------------------------------|--------------------|
| CloudTrail    | Capture all API calls                  | 1 trail free       |
| CloudWatch    | Log streaming + dashboard              | 5GB logs free      |
| EventBridge   | Real-time event routing                | Free at this scale |
| Lambda        | Detection + remediation engine         | 1M requests/month  |
| SNS           | Severity-tiered email alerts           | 1000 emails/month  |
| DynamoDB      | Incident log + recon counter           | 25GB free          |
| IAM           | Least privilege Lambda execution role  | Always free        |

---

## Threat Coverage

### 🔴 CRITICAL

| Threat | CloudTrail Event | Auto-Remediation |
|--------|-----------------|------------------|
| Root account login | ConsoleLogin | Alert only |
| CloudTrail logging disabled | StopLogging | ✅ Re-enables immediately |
| CloudTrail trail deleted | DeleteTrail | Alert only |
| AdministratorAccess attached to user | AttachUserPolicy | ✅ Detaches policy |

### 🟠 HIGH

| Threat | CloudTrail Event | Auto-Remediation |
|--------|-----------------|------------------|
| Console login without MFA | ConsoleLogin | Alert only |
| New IAM user created | CreateUser | Alert only |
| New access key created | CreateAccessKey | ✅ Deactivates key |
| S3 bucket ACL changed | PutBucketAcl | Alert only |
| S3 bucket policy changed | PutBucketPolicy | Alert only |

### 🟡 MEDIUM

| Threat | CloudTrail Event | Auto-Remediation |
|--------|-----------------|------------------|
| Secrets Manager secret accessed | GetSecretValue | Alert only |
| Security group opened to 0.0.0.0/0 | AuthorizeSecurityGroupIngress | Alert only |
| CloudTrail config modified | UpdateTrail | Alert only |
| Inline policy added to IAM role | PutRolePolicy | Alert only |
| IAM role trust policy modified | UpdateAssumeRolePolicy | Alert only |
| IAM access key deleted | DeleteAccessKey | Alert only |
| Permission recon (5+ AccessDenied in 5min) | AccessDenied pattern | Alert only |

---

## Alert Format

Every email alert includes a unique incident ID for DynamoDB cross-reference:

```
🚨 [CRITICAL] CloudTrail Logging Disabled
=======================================================

INCIDENT DETAILS
  Incident ID : A3F9B2C1
  Account     : 084149021663
  Region      : ap-south-2
  Time        : 2026-07-03T14:30:00Z
  Actor       : Arjun
  Event       : StopLogging
  Source IP   : x.x.x.x

WHAT HAPPENED
  An actor attempted to stop CloudTrail logging.
  This is a common attacker tactic to cover tracks
  before performing malicious actions.

ACTION TAKEN
  ✅ AUTO-REMEDIATED: CloudTrail logging re-enabled
     for trail 'cloud-threat-detection-trail'

=======================================================
AWS Cloud Threat Detection System
```

---

## DynamoDB Schema

### incident-log table

```
incident_id  (PK)  → 8-char UUID e.g. "A3F9B2C1"
timestamp    (SK)  → ISO 8601 UTC
severity           → CRITICAL / HIGH / MEDIUM
title              → human readable threat name
event_name         → CloudTrail eventName
actor              → IAM username or role
source_ip          → originating IP address
region             → AWS region of the event
action_taken       → remediation result or alert only
status             → OPEN
```

### recon-counter table

```
actor       (PK)   → IAM username or role ARN
count              → AccessDenied hits in current window
first_seen         → window start timestamp
last_seen          → most recent hit timestamp
```

Threshold: **5 AccessDenied errors in 5 minutes** → MEDIUM alert fires, counter resets.

---

## IAM — Least Privilege Policy

Lambda role is granted only the exact permissions needed for remediation:

```json
{
  "Statements": [
    "sns:Publish"               → 3 specific topic ARNs only,
    "cloudtrail:StartLogging"   → re-enable if stopped,
    "cloudtrail:GetTrailStatus" → verify trail state,
    "iam:DetachUserPolicy"      → remove admin policy,
    "iam:UpdateAccessKey"       → deactivate rogue keys,
    "dynamodb:PutItem/GetItem/UpdateItem" → specific table ARNs only,
    "logs:PutLogEvents"         → Lambda log group only
  ]
}
```

Full policy → `/iam/lambda-execution-policy.json`

---

## Key Engineering Decisions

**1. Single-region EventBridge catches IAM events**

IAM is a global AWS service and its events normally only flow through
EventBridge in us-east-1. However, with CloudTrail configured as a
multi-region trail with global service events enabled, IAM events are
delivered to the local region's CloudWatch Logs and picked up by the
ap-south-2 EventBridge rule directly — no cross-region setup needed.

**2. Single broad EventBridge rule → Lambda classifies**

Instead of many narrow EventBridge rules, one broad rule feeds all
events to Lambda. The THREAT_RULES dictionary handles classification,
severity scoring, and conditional matching. Easier to extend, easier
to debug.

**3. Three separate SNS topics by severity**

Independent subscription management per severity — mute MEDIUM alerts
at night without touching CRITICAL. Each topic maps to a different
email subscription.

**4. Recon detection via DynamoDB sliding window**

Lambda is stateless — it can't track patterns across invocations.
The recon-counter DynamoDB table maintains per-actor AccessDenied
counts with a 5-minute sliding window, enabling pattern-based
detection without GuardDuty's ML models.

**5. Incident ID ties email alert to DynamoDB record**

Every detected threat generates a short 8-char UUID. This appears
in the email subject line and is stored as the DynamoDB primary key —
allowing cross-reference between inbox alerts and the audit log.

---

## Repo Structure

```
cloud-threat-detection/
│
├── README.md
│
├── lambda/
│   └── lambda_function.py              ← full detection engine
│
├── eventbridge/
│   └── ap-south-2-rule.json            ← event pattern (all services)
│
├── iam/
│   └── lambda-execution-policy.json    ← least privilege policy
│
├── dynamodb/
│   ├── incident-log-schema.json        ← table definition
│   └── recon-counter-schema.json       ← table definition
│
├── cloudwatch/
│   └── dashboard-body.json             ← full dashboard JSON
│
├── docs/   
│   └── threat-catalog.md              ← all 15 threats documented
│
└── tests/
    └── test-events/
        ├── create-user.json
        ├── stop-logging.json
        ├── attach-admin-policy.json
        ├── console-login-root.json
        └── create-access-key.json
```

---

## Setup Guide

### Prerequisites

- AWS account (free tier)
- AWS CLI configured with IAM user credentials
- Python 3.12+

### Deployment Order

```
1. CloudTrail trail
   → Management events: All
   → Multi-region: ON
   → Global service events: ON (critical for IAM event capture)

2. CloudWatch Log Group linked to CloudTrail trail

3. S3 bucket for CloudTrail log archive (SSE-S3 encryption)

4. SNS topics × 3
   → critical-alerts
   → high-alerts
   → medium-alerts
   → subscribe email to each, confirm all 3

5. DynamoDB tables × 2 (on-demand billing)
   → incident-log  (PK: incident_id, SK: timestamp)
   → recon-counter (PK: actor)

6. Lambda function
   → Runtime: Python 3.12
   → Paste lambda_function.py
   → Update SNS ARNs at top of file
   → Timeout: 30 seconds

7. IAM policy attached to Lambda execution role
   → Use lambda-execution-policy.json

8. EventBridge rule in ap-south-2
   → Single broad rule → Lambda target

9. CloudWatch dashboard
   → Use dashboard-body.json via put-dashboard CLI command
```

### Configuration

Update these 3 lines in `lambda/lambda_function.py`:

```python
SNS_CRITICAL = "arn:aws:sns:YOUR_REGION:YOUR_ACCOUNT_ID:critical-alerts"
SNS_HIGH     = "arn:aws:sns:YOUR_REGION:YOUR_ACCOUNT_ID:high-alerts"
SNS_MEDIUM   = "arn:aws:sns:YOUR_REGION:YOUR_ACCOUNT_ID:medium-alerts"
```

Also update the boto3 client region:

```python
sns = boto3.client('sns',        region_name='YOUR_REGION')
iam = boto3.client('iam',        region_name='YOUR_REGION')
ct  = boto3.client('cloudtrail', region_name='YOUR_REGION')
ec2 = boto3.client('ec2',        region_name='YOUR_REGION')
s3  = boto3.client('s3',         region_name='YOUR_REGION')
ddb = boto3.resource('dynamodb', region_name='YOUR_REGION')
```

---

## Testing

Run these CLI commands to verify the full pipeline end-to-end:

```bash
# HIGH — new IAM user (wait 2-3 min for email)
aws iam create-user --user-name threat-test --region ap-south-2

# HIGH — access key created (auto-deactivates)
aws iam create-access-key --user-name threat-test --region ap-south-2

# Verify key was deactivated
aws iam list-access-keys --user-name threat-test --region ap-south-2

# CRITICAL — disable CloudTrail (auto re-enables)
aws cloudtrail stop-logging \
  --name YOUR_TRAIL_NAME --region ap-south-2

# Verify trail re-enabled
aws cloudtrail get-trail-status \
  --name YOUR_TRAIL_NAME --region ap-south-2

# Cleanup
aws iam delete-access-key \
  --user-name threat-test \
  --access-key-id KEY_ID_HERE \
  --region ap-south-2
aws iam delete-user --user-name threat-test --region ap-south-2
```

Check DynamoDB after each test:
```
DynamoDB → Tables → incident-log → Explore table items
```

---

---

## Built With

![AWS](https://img.shields.io/badge/AWS-CloudTrail-orange)
![AWS](https://img.shields.io/badge/AWS-EventBridge-orange)
![AWS](https://img.shields.io/badge/AWS-Lambda-orange)
![AWS](https://img.shields.io/badge/AWS-SNS-orange)
![AWS](https://img.shields.io/badge/AWS-DynamoDB-orange)
![AWS](https://img.shields.io/badge/AWS-CloudWatch-orange)
![Python](https://img.shields.io/badge/Python-3.12-blue)

**Region:** ap-south-2 (Hyderabad, India)  
**Cost:** $0 — fully within AWS free tier  
**Built during:** APSSDC AWS Cloud Internship
