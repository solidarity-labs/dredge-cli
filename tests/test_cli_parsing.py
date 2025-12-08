# tests/test_cli_parsing.py

import argparse

from dredge import cli as dredge_cli

def test_cli_has_expected_subcommands():
    parser = dredge_cli.build_parser()

    # Find the existing subparsers action without creating a new one
    subparsers_action = next(
        a for a in parser._actions if isinstance(a, argparse._SubParsersAction)
    )
    subparsers = subparsers_action.choices

    # Basic commands we expect to exist
    for cmd in [
        "aws-disable-access-key",
        "aws-disable-user",
        "aws-hunt-cloudtrail",
        "github-hunt-audit",
    ]:
        assert cmd in subparsers


def test_cli_parses_aws_hunt_cloudtrail_args():
    parser = dredge_cli.build_parser()
    args = parser.parse_args(
        [
            "--aws-profile",
            "backdoor",
            "--region",
            "us-east-1",
            "aws-hunt-cloudtrail",
            "--user",
            "alice",
            "--max-events",
            "10",
        ]
    )

    assert args.command == "aws-hunt-cloudtrail"
    assert args.user == "alice"
    assert args.max_events == 10
    assert args.aws_profile == "backdoor"
    assert args.aws_region == "us-east-1"
