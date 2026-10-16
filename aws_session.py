import re

import boto3

ROLE_ARN_RE = re.compile(r"^arn:aws:iam::\d{12}:role/[\w+=,.@/-]{1,128}$")

PERMISSIONS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["ec2:Describe*", "cloudwatch:GetMetricStatistics", "pricing:GetProducts"],
        "Resource": "*",
    }],
}


def trust_policy(principal_arn, external_id):
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": principal_arn},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
        }],
    }


def creds_for(role_arn, external_id):
    # The ONLY bare boto3.client() call allowed in the whole app.
    sts = boto3.client("sts")
    c = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="waste-scan",
        ExternalId=external_id,
        DurationSeconds=900,
    )["Credentials"]
    return {
        "aws_access_key_id": c["AccessKeyId"],
        "aws_secret_access_key": c["SecretAccessKey"],
        "aws_session_token": c["SessionToken"],
    }


def make_session(creds=None, profile=None, local=False):
    """The ONLY place a boto3.Session is created.
    Web path: pass creds. CLI path: pass local=True (uses your own profile).
    No creds and not local -> error, so the web app can never silently
    fall back to the server's own credentials."""
    if creds:
        return boto3.Session(**creds)
    if local:
        return boto3.Session(profile_name=profile)
    raise ValueError("No credentials supplied")


def session_for(role_arn, external_id):
    return make_session(creds_for(role_arn, external_id))


def verify(role_arn, external_id):
    creds = creds_for(role_arn, external_id)
    ident = make_session(creds).client("sts").get_caller_identity()
    if ":assumed-role/" not in ident["Arn"]:
        raise RuntimeError("Scan session is not running as the assumed role")
    return creds, ident