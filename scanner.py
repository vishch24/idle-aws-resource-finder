"""
Idle AWS Resource Finder for Learners - scanner module (v3).

Finds forgotten resources across ALL enabled regions (or just one):
  1. Idle EC2 instances (running, but CPU stayed under 5% for ~7 days)
  2. Stopped EC2 instances (no compute cost, but their disks are still billed)
  3. Unattached EBS volumes (status == "available")
  4. Elastic IPs that are not associated with anything
  5. Old EBS snapshots you own (older than 90 days)

Prices come from the AWS Price List API for each region. If that call is not
allowed or fails, the script falls back to rough built-in estimates and says so.

Read-only permissions needed:
  ec2:DescribeRegions, ec2:DescribeInstances, ec2:DescribeVolumes,
  ec2:DescribeAddresses, ec2:DescribeSnapshots, ec2:DescribeImages,
  cloudwatch:GetMetricStatistics,
  pricing:GetProducts   (optional, for exact regional prices)

It never deletes or stops anything. It only prints commands you can run yourself.

Usage:
    python scanner.py                      # all enabled regions
    python scanner.py --region ap-south-1  # one region only
    python scanner.py --profile myprofile
    python scanner.py --no-pricing-api     # skip live prices, use estimates
"""

import argparse
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

# import boto3
from aws_session import make_session

# The exchange rate is NOT fetched live. Set it yourself, for example:
#   export USD_TO_INR=89.5
USD_TO_INR = float(os.environ.get("USD_TO_INR", "88.0"))

HOURS_PER_MONTH = 730

# Public IPv4 addresses are charged hourly at a flat rate.
EIP_PRICE_PER_HOUR = 0.005

# ---- Fallback estimates (used only if the Price List API is unavailable) ---
# Rough ap-south-1 values from memory. Treat as estimates.
FALLBACK_EBS_PRICE_PER_GB = {"gp3": 0.0912, "gp2": 0.114}
FALLBACK_EBS_DEFAULT = 0.114
FALLBACK_EC2_PRICE_PER_HOUR = {
    "t2.micro": 0.0116,
    "t3.micro": 0.0104,
    "t2.small": 0.023,
    "t3.small": 0.0208,
    "t2.medium": 0.0464,
    "t3.medium": 0.0416,
}

# Snapshots older than this many days are listed as "old". It is a judgment
# call, not proof they are unused.
SNAPSHOT_MAX_AGE_DAYS = 90
# Flat estimate, USD per GB-month, for standard-tier snapshots. Snapshots are
# billed on data actually stored, which the API does not tell us, so the real
# bill is usually LOWER than this. Treated as an upper bound.
SNAPSHOT_PRICE_PER_GB = 0.05

# What "idle" means for EC2: the busiest day's average CPU stayed below this.
IDLE_CPU_THRESHOLD = 5.0
LOOKBACK_DAYS = 7
MIN_DAYS_OF_DATA = 5  # skip instances too new to judge

# Fail fast instead of hanging on one slow region.
CLIENT_CONFIG = Config(
    connect_timeout=5,
    read_timeout=20,
    retries={"max_attempts": 2, "mode": "standard"},
)

SRC_API = "AWS price list"
SRC_ESTIMATE = "estimate"
SRC_FLAT = "flat AWS rate"


def to_inr(usd):
    return round(usd * USD_TO_INR, 2)


def name_tag(tags):
    for tag in tags or []:
        if tag["Key"] == "Name":
            return tag["Value"]
    return "no-name"


# ---------------------------------------------------------------------------
# Prices
# ---------------------------------------------------------------------------
def on_demand_usd(price_list, unit):
    """Pull the first non-zero on-demand USD price with the given unit."""
    for raw in price_list:
        item = json.loads(raw) if isinstance(raw, str) else raw
        for term in item.get("terms", {}).get("OnDemand", {}).values():
            for dim in term["priceDimensions"].values():
                if dim.get("unit") == unit:
                    usd = float(dim["pricePerUnit"]["USD"])
                    if usd > 0:
                        return usd
    return None


class PriceBook:
    """Looks up regional prices once, caches them, falls back to estimates."""

    def __init__(self, session, use_api=True):
        self.client = None
        if use_api:
            # The Price List API only lives in a few regions. us-east-1 works.
            self.client = session.client("pricing", region_name="us-east-1", config=CLIENT_CONFIG)
        self.cache = {}

    def _filters(self, pairs):
        return [{"Type": "TERM_MATCH", "Field": k, "Value": v} for k, v in pairs]

    def _lookup(self, pairs, unit):
        """Return a USD price from the API, or None if unavailable."""
        client = self.client  # local copy: another thread may set self.client to None
        if client is None:
            return None
        try:
            resp = client.get_products(
                ServiceCode="AmazonEC2", Filters=self._filters(pairs), MaxResults=10
            )
            return on_demand_usd(resp.get("PriceList", []), unit)
        except (ClientError, BotoCoreError, KeyError, ValueError) as err:
            print(
                f"Note: live prices unavailable ({type(err).__name__}). "
                f"Using rough estimates. Add pricing:GetProducts to your IAM "
                f"policy for exact regional prices.",
                file=sys.stderr,
            )
            self.client = None  # stop retrying, avoid slow repeated failures
            return None

    def ebs_gb_month(self, region, volume_type):
        key = ("ebs", region, volume_type)
        if key not in self.cache:
            usd = self._lookup(
                [
                    ("productFamily", "Storage"),
                    ("regionCode", region),
                    ("volumeApiName", volume_type),
                ],
                "GB-Mo",
            )
            if usd is not None:
                self.cache[key] = (usd, SRC_API)
            else:
                est = FALLBACK_EBS_PRICE_PER_GB.get(volume_type, FALLBACK_EBS_DEFAULT)
                self.cache[key] = (est, SRC_ESTIMATE)
        return self.cache[key]

    def ec2_hour(self, region, instance_type):
        key = ("ec2", region, instance_type)
        if key not in self.cache:
            usd = self._lookup(
                [
                    ("productFamily", "Compute Instance"),
                    ("regionCode", region),
                    ("instanceType", instance_type),
                    ("operatingSystem", "Linux"),
                    ("tenancy", "Shared"),
                    ("preInstalledSw", "NA"),
                    ("capacitystatus", "Used"),
                ],
                "Hrs",
            )
            if usd is not None:
                self.cache[key] = (usd, SRC_API)
            elif instance_type in FALLBACK_EC2_PRICE_PER_HOUR:
                self.cache[key] = (
                    FALLBACK_EC2_PRICE_PER_HOUR[instance_type],
                    SRC_ESTIMATE,
                )
            else:
                self.cache[key] = (None, "unknown")
        return self.cache[key]


# ---------------------------------------------------------------------------
# Finders
# ---------------------------------------------------------------------------
def find_idle_instances(session, region, prices):
    ec2 = session.client("ec2", region_name=region, config=CLIENT_CONFIG)
    cw = session.client("cloudwatch", region_name=region, config=CLIENT_CONFIG)
    end = datetime.now(UTC)
    start = end - timedelta(days=LOOKBACK_DAYS)
    findings = []

    paginator = ec2.get_paginator("describe_instances")
    pages = paginator.paginate(
        Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
    )
    for page in pages:
        for reservation in page["Reservations"]:
            for inst in reservation["Instances"]:
                iid = inst["InstanceId"]
                stats = cw.get_metric_statistics(
                    Namespace="AWS/EC2",
                    MetricName="CPUUtilization",
                    Dimensions=[{"Name": "InstanceId", "Value": iid}],
                    StartTime=start,
                    EndTime=end,
                    Period=86400,  # one datapoint per day
                    Statistics=["Average"],
                )
                points = [p["Average"] for p in stats["Datapoints"]]
                if len(points) < MIN_DAYS_OF_DATA:
                    continue  # too new, or no data
                peak_day = max(points)
                if peak_day >= IDLE_CPU_THRESHOLD:
                    continue  # actually being used

                itype = inst["InstanceType"]
                hourly, source = prices.ec2_hour(region, itype)
                monthly_inr = to_inr(hourly * HOURS_PER_MONTH) if hourly else None
                findings.append(
                    {
                        "region": region,
                        "type": "EC2 instance (idle)",
                        "id": iid,
                        "detail": (
                            f"{name_tag(inst.get('Tags'))}, {itype}, "
                            f"busiest-day avg CPU {peak_day:.1f}%"
                        ),
                        "monthly_inr": monthly_inr,
                        "price_source": source,
                        "cleanup": (
                            f"aws ec2 stop-instances --instance-ids {iid} --region {region}"
                            f"  # reversible\n"
                            f"        aws ec2 terminate-instances --instance-ids {iid} "
                            f"--region {region}  # permanent"
                        ),
                    }
                )
    return findings


def find_stopped_instances(session, region, prices):
    """Stopped instances cost nothing for compute, but attached EBS disks keep
    billing. Those disks show as 'in-use', so the unattached-volume check
    never sees them."""
    ec2 = session.client("ec2", region_name=region, config=CLIENT_CONFIG)
    findings = []
    paginator = ec2.get_paginator("describe_instances")
    pages = paginator.paginate(
        Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
    )
    for page in pages:
        for reservation in page["Reservations"]:
            for inst in reservation["Instances"]:
                vol_ids = [
                    m["Ebs"]["VolumeId"]
                    for m in inst.get("BlockDeviceMappings", [])
                    if "Ebs" in m
                ]
                if not vol_ids:
                    continue
                total_gb, monthly_usd, sources = 0, 0.0, set()
                for vol in ec2.describe_volumes(VolumeIds=vol_ids)["Volumes"]:
                    per_gb, src = prices.ebs_gb_month(region, vol["VolumeType"])
                    total_gb += vol["Size"]
                    monthly_usd += vol["Size"] * per_gb
                    sources.add(src)
                source = SRC_API if sources == {SRC_API} else SRC_ESTIMATE

                iid = inst["InstanceId"]
                # e.g. "User initiated (2026-08-08 10:50:12 GMT)"
                match = re.search(r"\((\d{4}-\d{2}-\d{2})", inst.get("StateTransitionReason", ""))
                since = f", stopped since {match.group(1)}" if match else ""
                findings.append(
                    {
                        "region": region,
                        "type": "EC2 instance (stopped, disks still billed)",
                        "id": iid,
                        "detail": (
                            f"{name_tag(inst.get('Tags'))}, {inst['InstanceType']}, "
                            f"{total_gb} GB of disks{since}"
                        ),
                        "monthly_inr": to_inr(monthly_usd),
                        "price_source": source,
                        "cleanup": (
                            f"aws ec2 create-image --instance-id {iid} --name backup-{iid} "
                            f"--region {region}  # optional backup first\n"
                            f"        aws ec2 terminate-instances --instance-ids {iid} "
                            f"--region {region}  # permanent"
                        ),
                    }
                )
    return findings


def find_unattached_volumes(session, region, prices):
    ec2 = session.client("ec2", region_name=region, config=CLIENT_CONFIG)
    findings = []
    paginator = ec2.get_paginator("describe_volumes")
    pages = paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}])
    for page in pages:
        for vol in page["Volumes"]:
            size = vol["Size"]
            vtype = vol["VolumeType"]
            per_gb, source = prices.ebs_gb_month(region, vtype)
            vid = vol["VolumeId"]
            findings.append(
                {
                    "region": region,
                    "type": "EBS volume (unattached)",
                    "id": vid,
                    "detail": f"{size} GB {vtype}",
                    "monthly_inr": to_inr(size * per_gb),
                    "price_source": source,
                    "cleanup": (
                        f"aws ec2 create-snapshot --volume-id {vid} --region {region}"
                        f"  # optional backup first\n"
                        f"        aws ec2 delete-volume --volume-id {vid} --region {region}"
                    ),
                }
            )
    return findings


def find_old_snapshots(session, region):
    ec2 = session.client("ec2", region_name=region, config=CLIENT_CONFIG)
    now = datetime.now(UTC)

    old = []
    paginator = ec2.get_paginator("describe_snapshots")
    for page in paginator.paginate(OwnerIds=["self"]):
        for snap in page["Snapshots"]:
            age_days = (now - snap["StartTime"]).days
            if age_days >= SNAPSHOT_MAX_AGE_DAYS:
                old.append((snap, age_days))
    if not old:
        return []

    # Which snapshots back one of your AMIs? AWS refuses to delete those
    # until the AMI is deregistered.
    ami_for_snapshot = {}
    for image in ec2.describe_images(Owners=["self"])["Images"]:
        for mapping in image.get("BlockDeviceMappings", []):
            snap_id = mapping.get("Ebs", {}).get("SnapshotId")
            if snap_id:
                ami_for_snapshot[snap_id] = image["ImageId"]

    # Which source volumes still exist?
    existing_volumes = set()
    for page in ec2.get_paginator("describe_volumes").paginate():
        existing_volumes.update(v["VolumeId"] for v in page["Volumes"])

    findings = []
    for snap, age_days in old:
        sid = snap["SnapshotId"]
        size = snap["VolumeSize"]
        vol_id = snap.get("VolumeId", "")
        notes = [f"{size} GB", f"{age_days} days old"]
        # vol-ffffffff is what AWS shows for copied snapshots: source unknown
        if vol_id and vol_id != "vol-ffffffff":
            notes.append(
                "source volume still exists"
                if vol_id in existing_volumes
                else "source volume deleted"
            )
        delete_cmd = f"aws ec2 delete-snapshot --snapshot-id {sid} --region {region}"
        ami = ami_for_snapshot.get(sid)
        if ami:
            notes.append(f"used by AMI {ami}")
            cleanup = (
                f"aws ec2 deregister-image --image-id {ami} --region {region}"
                f"  # removes the AMI, permanent\n        {delete_cmd}"
            )
        else:
            cleanup = delete_cmd
        findings.append(
            {
                "region": region,
                "type": "EBS snapshot (old)",
                "id": sid,
                "detail": ", ".join(notes),
                "monthly_inr": to_inr(size * SNAPSHOT_PRICE_PER_GB),
                "price_source": SRC_ESTIMATE,
                "upper_bound": True,
                "cleanup": cleanup,
            }
        )
    return findings


def find_unused_elastic_ips(session, region):
    ec2 = session.client("ec2", region_name=region, config=CLIENT_CONFIG)
    findings = []
    monthly_inr = to_inr(EIP_PRICE_PER_HOUR * HOURS_PER_MONTH)
    for addr in ec2.describe_addresses()["Addresses"]:
        if "AssociationId" in addr:
            continue  # in use
        alloc_id = addr.get("AllocationId", "unknown")
        findings.append(
            {
                "region": region,
                "type": "Elastic IP (unused)",
                "id": alloc_id,
                "detail": addr.get("PublicIp", "?"),
                "monthly_inr": monthly_inr,
                "price_source": SRC_FLAT,
                "cleanup": (
                    f"aws ec2 release-address --allocation-id {alloc_id} "
                    f"--region {region}"
                ),
            }
        )
    return findings


def scan_region(session, region, prices):
    findings = []
    findings += find_idle_instances(session, region, prices)
    findings += find_stopped_instances(session, region, prices)
    findings += find_unattached_volumes(session, region, prices)
    findings += find_unused_elastic_ips(session, region)
    findings += find_old_snapshots(session, region)
    return findings


def list_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1", config=CLIENT_CONFIG)
    try:
        return sorted(r["RegionName"] for r in ec2.describe_regions()["Regions"])
    except ClientError as err:
        code = err.response["Error"]["Code"]
        raise RuntimeError(
            f"Could not list regions ({code}). Add ec2:DescribeRegions to your "
            f"IAM policy, or scan one region with --region."
        ) from err


def _scan_one(creds, profile, local, region, prices):
    # One Session per task: boto3 Sessions are not thread-safe, clients are.
    session = make_session(creds=creds, profile=profile, local=local)
    try:
        found = scan_region(session, region, prices)
        print(f"Scanned {region}", file=sys.stderr)
        return found, None
    except ClientError as err:
        return [], f"{region} ({err.response['Error']['Code']})"
    except BotoCoreError as err:
        return [], f"{region} ({type(err).__name__})"


def run_scan(creds=None, region=None, use_pricing_api=True, max_workers=8,
             profile=None, local=False):
    """region: None (all enabled regions), a single region string,
    or a list of region strings (from the Scan form's checkboxes)."""
    session = make_session(creds=creds, profile=profile, local=local)
    prices = PriceBook(session, use_api=use_pricing_api)
    
    if isinstance(region, list):
        regions = region
    elif isinstance(region, str):
        regions = [region]
    else:
        regions = list_regions(session)
 
    findings, skipped = [], []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for found, error in pool.map(
            lambda r: _scan_one(creds, profile, local, r, prices), regions
        ):
            findings += found
            if error:
                skipped.append(error)
    return findings, skipped


def main():
    parser = argparse.ArgumentParser(description="Find forgotten AWS resources")
    parser.add_argument("--region", default=None, help="scan one region only")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--no-pricing-api", action="store_true")
    args = parser.parse_args()

    started = time.perf_counter()
    try:
        findings, skipped = run_scan(
            # args.profile, args.region, use_pricing_api=not args.no_pricing_api

            region=args.region, profile=args.profile,
            use_pricing_api=not args.no_pricing_api, local=True,
        )
    except RuntimeError as err:
        print(err, file=sys.stderr)
        sys.exit(1)

    print()
    if not findings:
        print("Nothing forgotten in the scanned regions. Nice.")
    total = 0.0
    unknown_cost = 0
    upper_bound_count = 0
    for f in findings:
        print(f"[{f['type']}] {f['id']} in {f['region']} ({f['detail']})")
        if f["monthly_inr"] is None:
            unknown_cost += 1
            print("  Estimated waste: cost unknown for this instance type")
        else:
            total += f["monthly_inr"]
            if f.get("upper_bound"):
                upper_bound_count += 1
                label = f"up to Rs {f['monthly_inr']}/month"
            else:
                label = f"Rs {f['monthly_inr']}/month"
            print(f"  Estimated waste: {label} ({f['price_source']})")
        print(f"  Cleanup:         {f['cleanup']}\n")

    if findings:
        print(f"Total estimated waste: Rs {round(total, 2)}/month")
        if unknown_cost:
            print(f"({unknown_cost} finding(s) not included in the total: cost unknown)")
        if upper_bound_count:
            print(f"({upper_bound_count} snapshot estimate(s) are upper bounds, "
                  f"so the real total is likely lower)")
    if skipped:
        print(f"Skipped regions (no access or error): {', '.join(skipped)}")
    print(f"Scan took {time.perf_counter() - started:.1f}s.")
    print(f"Converted at Rs {USD_TO_INR}/USD (set USD_TO_INR to change). "
          f"Prices are estimates.")


if __name__ == "__main__":
    main()