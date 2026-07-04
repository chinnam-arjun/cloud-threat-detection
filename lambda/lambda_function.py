import json
import boto3
import os
import uuid
from datetime import datetime, timezone, timedelta

# ──────────────────────────────────────────────
# CONFIG — Replace with your actual ARNs
# ──────────────────────────────────────────────

SNS_CRITICAL = os.environ['SNS_CRITICAL_ARN']
SNS_HIGH     = os.environ['SNS_HIGH_ARN']
SNS_MEDIUM   = os.environ['SNS_MEDIUM_ARN']

SNS_TOPIC_MAP = {
    "CRITICAL" : SNS_CRITICAL,
    "HIGH"     : SNS_HIGH,
    "MEDIUM"   : SNS_MEDIUM
}

sns    = boto3.client('sns',          region_name='ap-south-2')
iam    = boto3.client('iam',          region_name='ap-south-2')
ct     = boto3.client('cloudtrail',   region_name='ap-south-2')
ec2    = boto3.client('ec2',          region_name='ap-south-2')
s3     = boto3.client('s3',           region_name='ap-south-2')
ddb    = boto3.resource('dynamodb', region_name='ap-south-2')

INCIDENT_TABLE = ddb.Table('incident-log')
RECON_TABLE    = ddb.Table('recon-counter')

# Recon threshold
RECON_THRESHOLD    = 5   # number of AccessDenied
RECON_WINDOW_MINS  = 5   # within this many minutes
# ──────────────────────────────────────────────
# THREAT RULES ENGINE
# ──────────────────────────────────────────────
# Each rule:
#   severity    → CRITICAL / HIGH / MEDIUM
#   title       → short human label
#   description → what happened and why it matters
#   check       → optional extra condition on event detail
#                 if omitted, event name match alone triggers it
#   remediation → auto / alert_only
# ──────────────────────────────────────────────

THREAT_RULES = {

    # ── CRITICAL ───────────────────────────────
    "StopLogging": {
        "severity"    : "CRITICAL",
        "title"       : "CloudTrail Logging Disabled",
        "description" : "An actor attempted to stop CloudTrail logging. "
                        "This is a common attacker tactic to cover tracks "
                        "before performing malicious actions.",
        "remediation" : "auto"
    },

    "DeleteTrail": {
        "severity"    : "CRITICAL",
        "title"       : "CloudTrail Trail Deleted",
        "description" : "A CloudTrail trail was deleted, completely removing "
                        "API audit logging. Immediate investigation required.",
        "remediation" : "alert_only"   # can't auto recreate, needs trail ARN context
    },

    "AttachUserPolicy": {
        "severity"    : "CRITICAL",
        "title"       : "AdministratorAccess Policy Attached to IAM User",
        "description" : "An IAM user was granted AdministratorAccess. "
                        "This is a privilege escalation attack pattern.",
        "check"       : lambda d: "AdministratorAccess" in str(
                            d.get("requestParameters", {})
                        ),
        "remediation" : "auto"
    },

    "ConsoleLogin_Root": {
        "severity"    : "CRITICAL",
        "title"       : "Root Account Console Login Detected",
        "description" : "The root account was used to log into the AWS console. "
                        "Root usage should be near-zero in a secure account.",
        "remediation" : "alert_only"   # cannot lock out root safely
    },


    # ── HIGH ───────────────────────────────────
    "ConsoleLogin_NoMFA": {
        "severity"    : "HIGH",
        "title"       : "Console Login Without MFA",
        "description" : "An IAM user logged into the console without "
                        "multi-factor authentication enabled.",
        "remediation" : "alert_only"
    },

    "CreateUser": {
        "severity"    : "HIGH",
        "title"       : "New IAM User Created",
        "description" : "A new IAM user was created. In a controlled environment "
                        "this should be rare and always expected.",
        "remediation" : "alert_only"
    },

    "CreateAccessKey": {
        "severity"    : "HIGH",
        "title"       : "New IAM Access Key Created",
        "description" : "A new programmatic access key was created. "
                        "Could indicate credential harvesting or backdoor setup.",
        "remediation" : "auto"
    },

    "PutBucketAcl": {
        "severity"    : "HIGH",
        "title"       : "S3 Bucket ACL Modified — Possible Public Exposure",
        "description" : "A bucket ACL change was made. If set to public-read "
                        "or public-read-write, data may be exposed.",
        "remediation" : "alert_only"
    },

    "PutBucketPolicy": {
        "severity"    : "HIGH",
        "title"       : "S3 Bucket Policy Modified",
        "description" : "A bucket policy was changed. Could allow unintended "
                        "public or cross-account access to S3 data.",
        "remediation" : "alert_only"
    },


    # ── MEDIUM ─────────────────────────────────
    "GetSecretValue": {
        "severity"    : "MEDIUM",
        "title"       : "Secrets Manager Secret Accessed",
        "description" : "A secret was retrieved from Secrets Manager. "
                        "Verify this matches expected application behavior.",
        "remediation" : "alert_only"
    },

    "AuthorizeSecurityGroupIngress": {
        "severity"    : "MEDIUM",
        "title"       : "Security Group Opened to 0.0.0.0/0",
        "description" : "An inbound security group rule was added that "
                        "allows traffic from any IP address.",
        "check"       : lambda d: "0.0.0.0/0" in str(
                            d.get("requestParameters", {})
                        ),
        "remediation" : "auto"
    },

    "UpdateTrail": {
        "severity"    : "MEDIUM",
        "title"       : "CloudTrail Trail Configuration Changed",
        "description" : "CloudTrail trail settings were modified. "
                        "Could reduce logging coverage.",
        "remediation" : "alert_only"
    },

    "PutRolePolicy": {
        "severity"    : "MEDIUM",
        "title"       : "Inline Policy Added to IAM Role",
        "description" : "An inline policy was directly attached to an IAM role. "
                        "May indicate privilege escalation attempt.",
        "remediation" : "alert_only"
    },

    "UpdateAssumeRolePolicy": {
        "severity"    : "MEDIUM",
        "title"       : "IAM Role Trust Policy Modified",
        "description" : "The trust policy of an IAM role was modified. "
                        "Could allow unintended principals to assume the role.",
        "remediation" : "alert_only"
    },

    "DeleteAccessKey": {
        "severity"    : "MEDIUM",
        "title"       : "IAM Access Key Deleted",
        "description" : "An access key was deleted. Could be cleanup after "
                        "credential compromise, or legitimate rotation.",
        "remediation" : "alert_only"
    },
}


# ──────────────────────────────────────────────
# DYNAMODB — Log Incident
# ──────────────────────────────────────────────
def log_incident(incident_id, severity, title, event_name,
                 actor, source_ip, region, action_taken):
    try:
        INCIDENT_TABLE.put_item(Item={
            "incident_id"  : incident_id,
            "timestamp"    : datetime.now(timezone.utc).isoformat(),
            "severity"     : severity,
            "title"        : title,
            "event_name"   : event_name,
            "actor"        : actor,
            "source_ip"    : source_ip,
            "region"       : region,
            "action_taken" : action_taken,
            "status"       : "OPEN"
        })
        print(f"Incident logged to DynamoDB: {incident_id}")
    except Exception as e:
        print(f"DynamoDB log failed: {str(e)}")


# ──────────────────────────────────────────────
# DYNAMODB — Recon Counter
# Tracks AccessDenied per actor, triggers alert
# after RECON_THRESHOLD hits in RECON_WINDOW_MINS
# ──────────────────────────────────────────────
def check_recon(actor, event_time):
    try:
        now        = datetime.now(timezone.utc)
        window_start = (now - timedelta(minutes=RECON_WINDOW_MINS)).isoformat()

        response = RECON_TABLE.get_item(Key={"actor": actor})
        item     = response.get("Item")

        if not item:
            # First AccessDenied from this actor
            RECON_TABLE.put_item(Item={
                "actor"      : actor,
                "count"      : 1,
                "first_seen" : now.isoformat(),
                "last_seen"  : now.isoformat()
            })
            return False

        first_seen = item.get("first_seen", now.isoformat())
        count      = int(item.get("count", 1))

        # Reset counter if outside window
        if first_seen < window_start:
            RECON_TABLE.put_item(Item={
                "actor"      : actor,
                "count"      : 1,
                "first_seen" : now.isoformat(),
                "last_seen"  : now.isoformat()
            })
            return False

        # Increment counter within window
        new_count = count + 1
        RECON_TABLE.update_item(
            Key              = {"actor": actor},
            UpdateExpression = "SET #c = :c, last_seen = :ls",
            ExpressionAttributeNames  = {"#c": "count"},
            ExpressionAttributeValues = {
                ":c"  : new_count,
                ":ls" : now.isoformat()
            }
        )

        print(f"Recon counter for {actor}: {new_count}/{RECON_THRESHOLD}")

        # Trigger alert if threshold hit
        if new_count >= RECON_THRESHOLD:
            # Reset after alerting
            RECON_TABLE.update_item(
                Key              = {"actor": actor},
                UpdateExpression = "SET #c = :c, first_seen = :fs",
                ExpressionAttributeNames  = {"#c": "count"},
                ExpressionAttributeValues = {
                    ":c"  : 0,
                    ":fs" : now.isoformat()
                }
            )
            return True   # trigger MEDIUM alert

        return False

    except Exception as e:
        print(f"Recon check failed: {str(e)}")
        return False


# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────
def get_actor(detail):
    identity    = detail.get("userIdentity", {})
    actor_type  = identity.get("type", "Unknown")
    if actor_type == "Root":
        return "ROOT ACCOUNT"
    elif actor_type == "IAMUser":
        return identity.get("userName", "Unknown IAM User")
    elif actor_type == "AssumedRole":
        arn = identity.get("arn", "")
        return f"AssumedRole: {arn.split('/')[-1]}"
    elif actor_type == "AWSService":
        return identity.get("invokedBy", "AWS Service")
    else:
        return identity.get("arn", "Unknown Actor")
# ──────────────────────────────────────────────
# HELPER — Extract actor identity from event
# ──────────────────────────────────────────────
def get_actor(detail):
    identity = detail.get("userIdentity", {})
    actor_type = identity.get("type", "Unknown")

    if actor_type == "Root":
        return "ROOT ACCOUNT"
    elif actor_type == "IAMUser":
        return identity.get("userName", "Unknown IAM User")
    elif actor_type == "AssumedRole":
        arn = identity.get("arn", "")
        return f"AssumedRole: {arn.split('/')[-1]}"
    elif actor_type == "AWSService":
        return identity.get("invokedBy", "AWS Service")
    else:
        return identity.get("arn", "Unknown Actor")


# ──────────────────────────────────────────────
# HELPER — Format SNS alert message
# ──────────────────────────────────────────────
def format_alert(severity, title, description, detail, action_taken, incident_id):
    severity_emoji = {
        "CRITICAL" : "🚨",
        "HIGH"     : "🟠",
        "MEDIUM"   : "🟡"
    }.get(severity, "⚠️")

    actor      = get_actor(detail)
    event_name = detail.get("eventName", "Unknown")
    region     = detail.get("awsRegion", "Unknown")
    source_ip  = detail.get("sourceIPAddress", "Unknown")
    event_time = detail.get("eventTime", datetime.now(timezone.utc).isoformat())
    account_id = detail.get("recipientAccountId", "Unknown")

    return f"""
{severity_emoji} [{severity}] {title}
{"=" * 55}

INCIDENT DETAILS
  Incident ID : {incident_id}
  Account   : {account_id}
  Region    : {region}
  Time      : {event_time}
  Actor     : {actor}
  Event     : {event_name}
  Source IP : {source_ip}

WHAT HAPPENED
  {description}

ACTION TAKEN
  {action_taken}

{"=" * 55}
AWS Cloud Threat Detection System
"""


# ──────────────────────────────────────────────
# REMEDIATION FUNCTIONS
# ──────────────────────────────────────────────

def remediate_stop_logging(detail):
    """Re-enable CloudTrail if it was stopped."""
    try:
        params = detail.get("requestParameters", {})
        trail_name = params.get("name", "")
        if trail_name:
            ct.start_logging(Name=trail_name)
            return f"✅ AUTO-REMEDIATED: CloudTrail logging re-enabled for trail '{trail_name}'"
        return "⚠️ Could not determine trail name — manual re-enable required"
    except Exception as e:
        return f"❌ Auto-remediation failed: {str(e)}"


def remediate_attach_admin_policy(detail):
    """Detach AdministratorAccess policy if auto-attached."""
    try:
        params   = detail.get("requestParameters", {})
        username = params.get("userName", "")
        policy   = params.get("policyArn", "")
        if username and "AdministratorAccess" in policy:
            iam.detach_user_policy(UserName=username, PolicyArn=policy)
            return f"✅ AUTO-REMEDIATED: AdministratorAccess detached from user '{username}'"
        return "⚠️ Could not extract user or policy — manual removal required"
    except Exception as e:
        return f"❌ Auto-remediation failed: {str(e)}"


def remediate_access_key(detail):
    """Deactivate newly created access key."""
    try:
        params    = detail.get("responseElements", {})
        key_data  = params.get("accessKey", {})
        access_key_id = key_data.get("accessKeyId", "")
        username      = key_data.get("userName", "")
        if access_key_id and username:
            iam.update_access_key(
                UserName    = username,
                AccessKeyId = access_key_id,
                Status      = "Inactive"
            )
            return f"✅ AUTO-REMEDIATED: Access key '{access_key_id}' for user '{username}' deactivated"
        return "⚠️ Could not extract key info — manual deactivation required"
    except Exception as e:
        return f"❌ Auto-remediation failed: {str(e)}"


def remediate_s3_public_acl(detail):
    """Block public access on S3 bucket if ACL changed."""
    try:
        params      = detail.get("requestParameters", {})
        bucket_name = params.get("bucketName", "")
        if bucket_name:
            s3.put_public_access_block(
                Bucket                         = bucket_name,
                PublicAccessBlockConfiguration = {
                    "BlockPublicAcls"       : True,
                    "IgnorePublicAcls"      : True,
                    "BlockPublicPolicy"     : True,
                    "RestrictPublicBuckets" : True
                }
            )
            return f"✅ AUTO-REMEDIATED: Public access blocked on bucket '{bucket_name}'"
        return "⚠️ Could not determine bucket name — manual review required"
    except Exception as e:
        return f"❌ Auto-remediation failed: {str(e)}"


def remediate_sg_open(detail):
    """Revoke security group rule opening to 0.0.0.0/0."""
    try:
        params   = detail.get("requestParameters", {})
        group_id = params.get("groupId", "")
        ip_perms = params.get("ipPermissions", {}).get("items", [])
        if group_id and ip_perms:
            ec2.revoke_security_group_ingress(
                GroupId        = group_id,
                IpPermissions  = ip_perms
            )
            return f"✅ AUTO-REMEDIATED: Open ingress rule revoked on security group '{group_id}'"
        return "⚠️ Could not extract SG info — manual review required"
    except Exception as e:
        return f"❌ Auto-remediation failed: {str(e)}"


# Map remediation actions to their functions
REMEDIATION_MAP = {
    "StopLogging"                  : remediate_stop_logging,
    "AttachUserPolicy"             : remediate_attach_admin_policy,
    "CreateAccessKey"              : remediate_access_key,
    "PutBucketAcl"                 : remediate_s3_public_acl,
    "AuthorizeSecurityGroupIngress": remediate_sg_open,
}


# ──────────────────────────────────────────────
# SPECIAL CASE HANDLER — ConsoleLogin
# ConsoleLogin needs extra checks (Root vs NoMFA)
# It's one event name but two different threats
# ──────────────────────────────────────────────
def handle_console_login(detail):
    identity = detail.get("userIdentity", {})
    mfa_used = detail.get(
        "additionalEventData", {}
    ).get("MFAUsed", "Yes")

    if identity.get("type") == "Root":
        return THREAT_RULES["ConsoleLogin_Root"]
    elif mfa_used == "No":
        return THREAT_RULES["ConsoleLogin_NoMFA"]
    return None   # login was normal — no alert


# ──────────────────────────────────────────────
# MAIN DETECTION FUNCTION
# ──────────────────────────────────────────────
def detect_threat(event_name, detail):
    if event_name == "ConsoleLogin":
        return handle_console_login(detail)

    # Handle AccessDenied recon detection
    error_code = detail.get("errorCode", "")
    if error_code == "AccessDenied":
        actor     = get_actor(detail)
        triggered = check_recon(actor, detail.get("eventTime", ""))
        if triggered:
            return {
                "severity"    : "MEDIUM",
                "title"       : "Possible Recon Activity Detected",
                "description" : f"Actor '{actor}' triggered {RECON_THRESHOLD}+ "
                                f"AccessDenied errors within {RECON_WINDOW_MINS} minutes. "
                                "This pattern indicates permission probing or recon.",
                "remediation" : "alert_only"
            }
        return None

    rule = THREAT_RULES.get(event_name)
    if not rule:
        return None

    check_fn = rule.get("check")
    if check_fn and not check_fn(detail):
        return None

    return rule

# ──────────────────────────────────────────────
# LAMBDA ENTRY POINT
# ──────────────────────────────────────────────
def lambda_handler(event, context):
    print("RAW EVENT:", json.dumps(event, indent=2))

    detail     = event.get("detail", {})
    event_name = detail.get("eventName", "")
    
    print(f"DEBUG eventName received: '{event_name}'")
    print(f"DEBUG source: '{event.get('source')}'")
    print(f"DEBUG detail-type: '{event.get('detail-type')}'")

    if not event_name:
        print("No eventName found — skipping")
        return {"statusCode": 200, "body": "No eventName"}

    print(f"Processing event: {event_name}")

    # ── Threat Detection ──────────────────────
    rule = detect_threat(event_name, detail)

    if not rule:
        print(f"No threat rule matched for: {event_name}")
        return {"statusCode": 200, "body": "No threat matched"}

    severity    = rule["severity"]
    title       = rule["title"]
    description = rule["description"]
    remediation = rule["remediation"]
    incident_id = str(uuid.uuid4())[:8].upper()

    print(f"THREAT DETECTED: {title} | Severity: {severity}")

    # ── Auto Remediation ──────────────────────
    action_taken = "No automated action taken — alert only."

    if remediation == "auto":
        remediate_fn = REMEDIATION_MAP.get(event_name)
        if remediate_fn:
            action_taken = remediate_fn(detail)
            print(f"Remediation result: {action_taken}")

    # ── Log to DynamoDB ───────────────────────
    log_incident(
        incident_id  = incident_id,
        severity     = severity,
        title        = title,
        event_name   = event_name,
        actor        = get_actor(detail),
        source_ip    = detail.get("sourceIPAddress", "Unknown"),
        region       = detail.get("awsRegion", "Unknown"),
        action_taken = action_taken
    )

    # ── Send SNS Alert ────────────────────────
    topic_arn = SNS_TOPIC_MAP.get(severity, SNS_MEDIUM)
    message   = format_alert(
        severity, title, description, detail, action_taken, incident_id
    )

    sns.publish(
        TopicArn = topic_arn,
        Subject  = f"[{severity}] {title}",
        Message  = message
    )

    print(f"Alert sent to {severity} SNS topic")

    return {
        "statusCode" : 200,
        "body"       : json.dumps({
            "incident_id" : incident_id,
            "threat"   : title,
            "severity" : severity,
            "action"   : action_taken
        })
    }
    
    
