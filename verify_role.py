import sys

from botocore.exceptions import ClientError

from aws_session import session_for

role_arn, external_id = sys.argv[1], sys.argv[2]
s = session_for(role_arn, external_id)

arn = s.client("sts").get_caller_identity()["Arn"]
print("scan identity:", arn)
assert ":assumed-role/" in arn, "FAIL: not running as the assumed role"

try:
    s.client("s3").list_buckets()
    print("FAIL: scan session can list S3, role is too broad")
    sys.exit(1)
except ClientError as e:
    code = e.response["Error"]["Code"]
    print("s3 negative test:", code)
    assert code == "AccessDenied"

s.client("ec2", region_name="ap-south-1").describe_volumes(MaxResults=5)
print("ec2 describe works. PASS")