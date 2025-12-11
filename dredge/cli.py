#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import csv
import sys
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from dateutil.relativedelta import relativedelta
from typing import Optional

# Library imports – adjust if your package paths differ
from dredge import Dredge, DredgeConfig
from dredge.auth import AwsAuthConfig
from dredge.github_ir.config import GitHubIRConfig

from importlib.metadata import version, PackageNotFoundError
# ------------- helpers -------------


def parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    v = value.strip()
    # Allow 'Z' suffix
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid datetime format: {value}. Use ISO 8601, e.g. 2025-01-01T12:00:00+00:00"
        )


def print_result(result, output: str = "json") -> None:
    """
    Print an OperationResult in the desired format.

    output: "json" (default) or "csv"
    """
    # Normalise to a dict first
    try:
        data = asdict(result)
    except TypeError:
        data = result

    if output == "json":
        print(json.dumps(data, indent=2, default=str))
        return

    if output == "csv":
        # Try to find a list-like payload to tabularise
        details = data.get("details", {}) if isinstance(data, dict) else {}
        events = None

        # Common hunt payload keys
        for key in ("events", "entries", "results"):
            if isinstance(details.get(key), list):
                events = details[key]
                break

        # If we don't have a sensible list, fall back to JSON
        if not events:
            print(json.dumps(data, indent=2, default=str))
            return

        # Collect all fieldnames across events
        fieldnames = set()
        for ev in events:
            if isinstance(ev, dict):
                fieldnames.update(ev.keys())

        fieldnames = sorted(fieldnames)

        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        for ev in events:
            if isinstance(ev, dict):
                writer.writerow(ev)
            else:
                # Best effort: dump non-dict as a single 'value' column
                writer.writerow({"value": str(ev)})

        return

    # Fallback if an unknown output format sneaks in
    print(json.dumps(data, indent=2, default=str))



def build_aws_auth_from_args(args: argparse.Namespace) -> Optional[AwsAuthConfig]:
    # If nothing is set, return None (Dredge will use default AWS chain)
    if not any(
        [
            args.aws_profile,
            args.aws_access_key_id,
            args.aws_secret_access_key,
            args.aws_session_token,
            args.aws_role_arn,
        ]
    ):
        return None

    return AwsAuthConfig(
        access_key_id=args.aws_access_key_id,
        secret_access_key=args.aws_secret_access_key,
        session_token=args.aws_session_token,
        profile_name=args.aws_profile,
        role_arn=args.aws_role_arn,
        external_id=args.aws_external_id,
        region_name=args.aws_region,
    )


def build_github_config_from_args(args: argparse.Namespace) -> Optional[GitHubIRConfig]:
    if not args.github_org and not args.github_enterprise:
        return None

    return GitHubIRConfig(
        org=args.github_org,
        enterprise=args.github_enterprise,
        token=args.github_token or None,
    )


# ------------- AWS command handlers -------------


def handle_aws_disable_access_key(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.disable_access_key(
        user_name=args.user,
        access_key_id=args.access_key_id,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_delete_access_key(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.delete_access_key(
        user_name=args.user,
        access_key_id=args.access_key_id,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_disable_user(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.disable_user(args.user)
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_delete_user(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.delete_user(args.user)
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_disable_role(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.disable_role(args.role)
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_block_s3_account(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.block_s3_public_access(
        account_id=args.account_id,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_block_s3_bucket(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.block_s3_bucket_public_access(
        bucket_name=args.bucket,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_block_s3_object(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.block_s3_object_public_access(
        bucket_name=args.bucket,
        key=args.key,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_isolate_ec2(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    res = dredge.aws_ir.response.isolate_ec2_instances(
        instance_ids=args.instance_ids,
        vpc_id=args.vpc_id,
    )
    print_result(res, output=getattr(args, "output", "json"))


def handle_aws_hunt_cloudtrail(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)
    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
    )
    # Relative ranges
    if args.week_ago or args.month_ago:
        start, end = compute_relative_range(
            weeks_ago=args.week_ago,
            months_ago=args.month_ago,
        )
    else:
        if args.today:
            now = datetime.now(timezone.utc)
            start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            end = now
        else:
            start = parse_iso_datetime(args.start_time)
            end = parse_iso_datetime(args.end_time)

    res = dredge.aws_ir.hunt.lookup_events(
        user_name=args.user,
        access_key_id=args.access_key_id,
        event_name=args.event_name,
        source_ip=args.source_ip,
        start_time=start,
        end_time=end,
        max_events=args.max_events,
    )
    print_result(res, output=getattr(args, "output", "json"))


# ------------- GitHub command handlers -------------


def handle_github_hunt_audit(args: argparse.Namespace) -> None:
    auth = build_aws_auth_from_args(args)  # optional; might be unused
    github_cfg = build_github_config_from_args(args)
    if github_cfg is None:
        raise SystemExit("You must provide --github-org or --github-enterprise")

    dredge = Dredge(
        auth=auth,
        config=DredgeConfig(region_name=args.aws_region, dry_run=args.dry_run),
        github_config=github_cfg,
    )

    if dredge.github_ir is None:
        raise SystemExit("GitHub IR not configured")

    if args.today:
        start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        end = datetime.now(timezone.utc)

    elif args.week_ago or args.month_ago:
        start, end = compute_relative_range(
            weeks_ago=args.week_ago,
            months_ago=args.month_ago,
        )

    else:
        start = parse_iso_datetime(args.start_time)
        end = parse_iso_datetime(args.end_time)

    res = dredge.github_ir.hunt.search_audit_log(
        actor=args.actor,
        action=args.action,
        repo=args.repo,
        source_ip=args.source_ip,
        start_time=start,
        end_time=end,
        include=args.include,
        max_events=args.max_events,
    )

    print_result(res, output=getattr(args, "output", "json"))


# ------------- argparse wiring -------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dredge-cli",
        description="Dredge incident response CLI (AWS + GitHub)",
    )

    # Global / AWS options
    parser.add_argument(
        "--aws-region", "--region",
        dest="aws_region",
        help="AWS region (e.g. us-east-1)",
        default=None,
    )    
    parser.add_argument("--aws-profile", help="AWS profile name", default=None)
    parser.add_argument("--aws-access-key-id", default=None)
    parser.add_argument("--aws-secret-access-key", default=None)
    parser.add_argument("--aws-session-token", default=None)
    parser.add_argument("--aws-role-arn", default=None)
    parser.add_argument("--aws-external-id", default=None)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not make changes, only simulate (where supported)",
    )

    # GitHub-global options (used when github subcommands are run)
    parser.add_argument("--github-org", default=None, help="GitHub organization slug")
    parser.add_argument("--github-enterprise", default=None, help="GitHub enterprise slug")
    parser.add_argument(
        "--github-token",
        default=None,
        help="GitHub token (otherwise uses env var configured in GitHubIRConfig)",
    )

    # --version flag
    try:
        dredge_version = version("dredge")
    except PackageNotFoundError:
        dredge_version = "development"

    parser.add_argument(
        "--version",
        action="version",
        version=f"dredge {dredge_version}",
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- AWS response subcommands ---

    p = subparsers.add_parser("aws-disable-access-key", help="Disable an IAM access key")
    p.add_argument("--user", required=True, help="IAM username")
    p.add_argument("--access-key-id", required=True, help="Access key ID")
    p.set_defaults(func=handle_aws_disable_access_key)

    p = subparsers.add_parser("aws-delete-access-key", help="Delete an IAM access key")
    p.add_argument("--user", required=True, help="IAM username")
    p.add_argument("--access-key-id", required=True, help="Access key ID")
    p.set_defaults(func=handle_aws_delete_access_key)

    p = subparsers.add_parser("aws-disable-user", help="Disable an IAM user")
    p.add_argument("--user", required=True, help="IAM username")
    p.set_defaults(func=handle_aws_disable_user)

    p = subparsers.add_parser("aws-delete-user", help="Delete an IAM user")
    p.add_argument("--user", required=True, help="IAM username")
    p.set_defaults(func=handle_aws_delete_user)

    p = subparsers.add_parser("aws-disable-role", help="Disable an IAM role")
    p.add_argument("--role", required=True, help="IAM role name")
    p.set_defaults(func=handle_aws_disable_role)

    p = subparsers.add_parser(
        "aws-block-s3-account", help="Block S3 public access at account level"
    )
    p.add_argument("--account-id", required=True, help="AWS account ID")
    p.set_defaults(func=handle_aws_block_s3_account)

    p = subparsers.add_parser(
        "aws-block-s3-bucket", help="Make an S3 bucket private / block public access"
    )
    p.add_argument("--bucket", required=True, help="Bucket name")
    p.set_defaults(func=handle_aws_block_s3_bucket)

    p = subparsers.add_parser(
        "aws-block-s3-object", help="Make a specific S3 object private"
    )
    p.add_argument("--bucket", required=True, help="Bucket name")
    p.add_argument("--key", required=True, help="Object key")
    p.set_defaults(func=handle_aws_block_s3_object)

    p = subparsers.add_parser(
        "aws-isolate-ec2", help="Network-isolate EC2 instances (forensic SG)"
    )
    p.add_argument(
        "instance_ids",
        nargs="+",
        help="One or more EC2 instance IDs",
    )
    p.add_argument(
        "--vpc-id",
        default=None,
        help="Optional VPC ID (otherwise inferred from first instance)",
    )
    p.set_defaults(func=handle_aws_isolate_ec2)

    # --- AWS hunt (CloudTrail) ---

    p = subparsers.add_parser(
        "aws-hunt-cloudtrail", help="Hunt CloudTrail events with simple filters"
    )
    p.add_argument("--user", default=None, help="CloudTrail Username")
    p.add_argument("--access-key-id", default=None, help="AccessKeyId")
    p.add_argument("--event-name", default=None, help="Event name (e.g. ConsoleLogin)")
    p.add_argument("--source-ip", default=None, help="Source IP address")
    p.add_argument("--start-time", default=None, help="Start time (ISO 8601)")
    p.add_argument("--end-time", default=None, help="End time (ISO 8601)")
    p.add_argument(
        "--max-events",
        type=int,
        default=500,
        help="Maximum number of events to return",
    )
    p.set_defaults(func=handle_aws_hunt_cloudtrail)
    p.add_argument(
        "--output",
        choices=["json", "csv"],
        default="json",
        help="Output format (json or csv, default json)",
    )
    p.add_argument(
        "--today",
        action="store_true",
        help="Search only today's CloudTrail events (UTC)",
    )   
    p.add_argument("--week-ago", type=int, help="Return events from N weeks ago until now")
    p.add_argument("--month-ago", type=int, help="Return events from N months ago until now")

    p.set_defaults(func=handle_aws_hunt_cloudtrail)

    # --- GitHub hunt ---

    p = subparsers.add_parser(
        "github-hunt-audit", help="Hunt GitHub org/enterprise audit logs"
    )
    p.add_argument("--actor", default=None, help="GitHub username (actor)")
    p.add_argument("--action", default=None, help="Audit action (e.g. repo.create)")
    p.add_argument("--repo", default=None, help="Repository (e.g. org/repo)")
    p.add_argument("--source-ip", default=None, help="Actor IP address")
    p.add_argument(
        "--include",
        default=None,
        help='Include filter: "web", "git", or "all" (default from config)',
    )
    p.add_argument("--start-time", default=None, help="Start time (ISO 8601)")
    p.add_argument("--end-time", default=None, help="End time (ISO 8601)")
    p.add_argument(
        "--max-events",
        type=int,
        default=500,
        help="Maximum number of events to return",
    )
    p.add_argument(
        "--output",
        choices=["json", "csv"],
        default="json",
        help="Output format (json or csv, default json)",
    )
    p.add_argument(
        "--today",
        action="store_true",
        help="Search only today's events",
    )

    p.add_argument("--week-ago", type=int, help="Return events from N weeks ago until now")
    p.add_argument("--month-ago", type=int, help="Return events from N months ago until now")
    
    p.set_defaults(func=handle_github_hunt_audit)

    return parser


def compute_relative_range(weeks_ago: int = None, months_ago: int = None):
    """
    Returns (start, end) datetimes in UTC based on relative offsets.
    - weeks_ago N → from N weeks ago until now
    - months_ago N → from N months ago until now
    """
    now = datetime.now(timezone.utc)

    if weeks_ago is not None:
        start = now - timedelta(weeks=weeks_ago)
        return start, now

    if months_ago is not None:
        start = now - relativedelta(months=months_ago)
        return start, now

    return None, None


def main():
    parser = build_parser()
    args = parser.parse_args()
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        raise SystemExit(1)
    func(args)

if __name__ == "__main__":
    main()

