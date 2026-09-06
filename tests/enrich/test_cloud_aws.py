from __future__ import annotations

from datetime import UTC, datetime

import boto3
from botocore.stub import Stubber

from kiyooo.enrich.cloud_aws import (
    enumerate_cloudfront_distributions,
    enumerate_ec2_instances,
    enumerate_load_balancers,
    enumerate_s3_buckets,
    get_account_id,
)

_ACCOUNT_ID = "111122223333"


def test_get_account_id() -> None:
    client = boto3.client("sts", region_name="us-east-1")
    with Stubber(client) as stubber:
        stubber.add_response(
            "get_caller_identity",
            {
                "UserId": "AIDAEXAMPLE",
                "Account": _ACCOUNT_ID,
                "Arn": "arn:aws:iam::111122223333:user/x",
            },
        )
        assert get_account_id(client) == _ACCOUNT_ID


def test_enumerate_ec2_instances_maps_public_ip_tags_and_security_groups() -> None:
    client = boto3.client("ec2", region_name="us-east-1")
    with Stubber(client) as stubber:
        stubber.add_response(
            "describe_instances",
            {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-0abc123",
                                "PublicIpAddress": "93.184.216.34",
                                "Tags": [{"Key": "Owner", "Value": "infra-team"}],
                                "SecurityGroups": [{"GroupId": "sg-1", "GroupName": "default"}],
                            },
                            {
                                "InstanceId": "i-0no-public-ip",
                            },
                        ]
                    }
                ]
            },
        )
        matches = enumerate_ec2_instances(client, _ACCOUNT_ID)

    assert len(matches) == 1
    match = matches[0]
    assert match.asset_value == "93.184.216.34"
    assert match.resource_id == "i-0abc123"
    assert match.resource_type == "ec2_instance"
    assert match.tags == {"Owner": "infra-team"}
    assert match.security_groups == ["sg-1"]


def test_enumerate_load_balancers_maps_dns_name_and_tags() -> None:
    client = boto3.client("elbv2", region_name="us-east-1")
    arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/abc123"
    with Stubber(client) as stubber:
        stubber.add_response(
            "describe_load_balancers",
            {
                "LoadBalancers": [
                    {
                        "LoadBalancerArn": arn,
                        "DNSName": "web-lb-123.us-east-1.elb.amazonaws.com",
                    }
                ]
            },
        )
        stubber.add_response(
            "describe_tags",
            {"TagDescriptions": [{"ResourceArn": arn, "Tags": [{"Key": "Team", "Value": "web"}]}]},
        )
        matches = enumerate_load_balancers(client, _ACCOUNT_ID)

    assert len(matches) == 1
    match = matches[0]
    assert match.asset_value == "web-lb-123.us-east-1.elb.amazonaws.com"
    assert match.resource_type == "elb"
    assert match.tags == {"Team": "web"}


def test_enumerate_s3_buckets_maps_name_and_tags() -> None:
    client = boto3.client("s3", region_name="us-east-1")
    with Stubber(client) as stubber:
        stubber.add_response("list_buckets", {"Buckets": [{"Name": "acmecorp-reports"}]})
        stubber.add_response(
            "get_bucket_tagging",
            {"TagSet": [{"Key": "Owner", "Value": "data-platform"}]},
            expected_params={"Bucket": "acmecorp-reports"},
        )
        matches = enumerate_s3_buckets(client, _ACCOUNT_ID)

    assert len(matches) == 1
    match = matches[0]
    assert match.asset_value == "acmecorp-reports"
    assert match.resource_type == "s3_bucket"
    assert match.tags == {"Owner": "data-platform"}


def test_enumerate_s3_buckets_no_tag_set_returns_empty_tags() -> None:
    client = boto3.client("s3", region_name="us-east-1")
    with Stubber(client) as stubber:
        stubber.add_response("list_buckets", {"Buckets": [{"Name": "untagged-bucket"}]})
        stubber.add_client_error(
            "get_bucket_tagging",
            service_error_code="NoSuchTagSet",
            expected_params={"Bucket": "untagged-bucket"},
        )
        matches = enumerate_s3_buckets(client, _ACCOUNT_ID)

    assert len(matches) == 1
    assert matches[0].tags == {}


def test_enumerate_cloudfront_distributions_maps_domain_and_tags() -> None:
    client = boto3.client("cloudfront", region_name="us-east-1")
    arn = "arn:aws:cloudfront::111122223333:distribution/E123EXAMPLE"
    with Stubber(client) as stubber:
        stubber.add_response(
            "list_distributions",
            {
                "DistributionList": {
                    "Marker": "",
                    "MaxItems": 100,
                    "IsTruncated": False,
                    "Quantity": 1,
                    "Items": [
                        {
                            "Id": "E123EXAMPLE",
                            "ARN": arn,
                            "Status": "Deployed",
                            "LastModifiedTime": datetime.now(UTC),
                            "DomainName": "d123example.cloudfront.net",
                            "Aliases": {"Quantity": 0, "Items": []},
                            "Origins": {
                                "Quantity": 1,
                                "Items": [
                                    {
                                        "Id": "origin1",
                                        "DomainName": "origin.example.com",
                                    }
                                ],
                            },
                            "DefaultCacheBehavior": {
                                "TargetOriginId": "origin1",
                                "ViewerProtocolPolicy": "redirect-to-https",
                            },
                            "CacheBehaviors": {"Quantity": 0},
                            "CustomErrorResponses": {"Quantity": 0},
                            "Comment": "",
                            "PriceClass": "PriceClass_All",
                            "Enabled": True,
                            "ViewerCertificate": {"CloudFrontDefaultCertificate": True},
                            "Restrictions": {
                                "GeoRestriction": {"RestrictionType": "none", "Quantity": 0}
                            },
                            "WebACLId": "",
                            "HttpVersion": "http2",
                            "IsIPV6Enabled": True,
                            "Staging": False,
                        }
                    ],
                }
            },
        )
        stubber.add_response(
            "list_tags_for_resource",
            {"Tags": {"Items": [{"Key": "Owner", "Value": "web-team"}]}},
            expected_params={"Resource": arn},
        )
        matches = enumerate_cloudfront_distributions(client, _ACCOUNT_ID)

    assert len(matches) == 1
    match = matches[0]
    assert match.asset_value == "d123example.cloudfront.net"
    assert match.resource_type == "cloudfront_distribution"
    assert match.tags == {"Owner": "web-team"}
