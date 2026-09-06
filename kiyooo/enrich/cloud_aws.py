"""AWS cloud enrichment — read-only, maps public IPs,
ELB DNS names, S3 buckets, and CloudFront distributions to their owning AWS
account, resource, tags, and (for EC2) security groups. GCP/Azure aren't
implemented this stage — see `cloud_gcp.py`/`cloud_azure.py` — only AWS's
SDK ships a `Stubber` that lets this module have genuine tests without a
live account or network call; the other two would be unverifiable code, not
just untested code.

Every boto3 call here is a `describe_*`/`list_*`/`get_*` — nothing that
creates, modifies, or deletes. This is enrichment, not scanning: the AWS
account is read via credentials the org itself supplies, not probed like a
target.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_cloudfront.client import CloudFrontClient
    from mypy_boto3_ec2.client import EC2Client
    from mypy_boto3_elbv2.client import ElasticLoadBalancingv2Client
    from mypy_boto3_s3.client import S3Client
    from mypy_boto3_sts.client import STSClient


@dataclass(frozen=True, slots=True)
class CloudResourceMatch:
    asset_value: str  # the IP/hostname/bucket name this resource is reachable as
    provider: str  # "aws"
    account_id: str
    resource_id: str
    resource_type: str  # ec2_instance | elb | s3_bucket | cloudfront_distribution
    tags: dict[str, str]
    security_groups: list[str] = field(default_factory=list)


def _tags_from_list(raw: list[Any] | None) -> dict[str, str]:
    """Each AWS service's SDK stubs define their own structurally-identical
    but nominally distinct `Tag` TypedDict (EC2's, ELB's, S3's, CloudFront's
    all differ as static types even though every one is `{Key, Value}` at
    runtime) — `Any` here is a deliberate, narrow boundary-typing choice
    rather than fighting four incompatible TypedDicts for a two-line loop.
    """
    if not raw:
        return {}
    return {item["Key"]: item["Value"] for item in raw if "Key" in item}


def get_account_id(sts_client: STSClient) -> str:
    return sts_client.get_caller_identity()["Account"]


def enumerate_ec2_instances(ec2_client: EC2Client, account_id: str) -> list[CloudResourceMatch]:
    matches: list[CloudResourceMatch] = []
    paginator = ec2_client.get_paginator("describe_instances")
    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                public_ip = instance.get("PublicIpAddress")
                if not public_ip:
                    continue
                security_groups = [
                    sg["GroupId"] for sg in instance.get("SecurityGroups", []) if "GroupId" in sg
                ]
                matches.append(
                    CloudResourceMatch(
                        asset_value=public_ip,
                        provider="aws",
                        account_id=account_id,
                        resource_id=instance.get("InstanceId", ""),
                        resource_type="ec2_instance",
                        tags=_tags_from_list(instance.get("Tags")),
                        security_groups=security_groups,
                    )
                )
    return matches


def enumerate_load_balancers(
    elbv2_client: ElasticLoadBalancingv2Client, account_id: str
) -> list[CloudResourceMatch]:
    matches: list[CloudResourceMatch] = []
    paginator = elbv2_client.get_paginator("describe_load_balancers")
    for page in paginator.paginate():
        load_balancers = page.get("LoadBalancers", [])
        arns = [lb["LoadBalancerArn"] for lb in load_balancers if lb.get("DNSName")]
        tags_by_arn: dict[str, dict[str, str]] = {}
        if arns:
            tag_resp = elbv2_client.describe_tags(ResourceArns=arns)
            for desc in tag_resp.get("TagDescriptions", []):
                arn = desc.get("ResourceArn")
                if arn:
                    tags_by_arn[arn] = _tags_from_list(desc.get("Tags"))
        for lb in load_balancers:
            dns_name = lb.get("DNSName")
            if not dns_name:
                continue
            arn = lb.get("LoadBalancerArn", "")
            matches.append(
                CloudResourceMatch(
                    asset_value=dns_name,
                    provider="aws",
                    account_id=account_id,
                    resource_id=arn,
                    resource_type="elb",
                    tags=tags_by_arn.get(arn, {}),
                )
            )
    return matches


def enumerate_s3_buckets(s3_client: S3Client, account_id: str) -> list[CloudResourceMatch]:
    matches: list[CloudResourceMatch] = []
    response = s3_client.list_buckets()
    for bucket in response.get("Buckets", []):
        name = bucket.get("Name")
        if not name:
            continue
        try:
            tag_resp = s3_client.get_bucket_tagging(Bucket=name)
            tags = _tags_from_list(tag_resp.get("TagSet"))
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchTagSet":
                raise
            tags = {}
        matches.append(
            CloudResourceMatch(
                asset_value=name,
                provider="aws",
                account_id=account_id,
                resource_id=name,
                resource_type="s3_bucket",
                tags=tags,
            )
        )
    return matches


def enumerate_cloudfront_distributions(
    cloudfront_client: CloudFrontClient, account_id: str
) -> list[CloudResourceMatch]:
    matches: list[CloudResourceMatch] = []
    paginator = cloudfront_client.get_paginator("list_distributions")
    for page in paginator.paginate():
        items = page.get("DistributionList", {}).get("Items", [])
        for item in items:
            domain_name = item.get("DomainName")
            arn = item.get("ARN")
            if not domain_name or not arn:
                continue
            tag_resp = cloudfront_client.list_tags_for_resource(Resource=arn)
            tag_items = tag_resp.get("Tags", {}).get("Items", [])
            matches.append(
                CloudResourceMatch(
                    asset_value=domain_name,
                    provider="aws",
                    account_id=account_id,
                    resource_id=item.get("Id", ""),
                    resource_type="cloudfront_distribution",
                    tags=_tags_from_list(tag_items),
                )
            )
    return matches


def enumerate_all(
    *,
    ec2_client: EC2Client,
    elbv2_client: ElasticLoadBalancingv2Client,
    s3_client: S3Client,
    cloudfront_client: CloudFrontClient,
    sts_client: STSClient,
) -> list[CloudResourceMatch]:
    account_id = get_account_id(sts_client)
    return [
        *enumerate_ec2_instances(ec2_client, account_id),
        *enumerate_load_balancers(elbv2_client, account_id),
        *enumerate_s3_buckets(s3_client, account_id),
        *enumerate_cloudfront_distributions(cloudfront_client, account_id),
    ]
