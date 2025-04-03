# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Command line utility to process Cloud logs."""

import argparse
import logging
import sys

from cloud_logs.gcp.log import GoogleCloudLog


def AddGCPParser(subparser):
    """GCP command line arguments."""
    gcp_parser = subparser.add_parser("gcp", help="Google Cloud audit log parser.")

    gcp_parser.add_argument(
        "--source_file",
        "--source-file",
        dest="source_file",
        action="store",
        default="",
        help="Cloud log as JSONL",
    )

    gcp_parser.add_argument(
        "--output_file",
        "--output-file",
        dest="output_file",
        action="store",
        default="",
        help="Timesketch compatible JSONL Cloud log",
    )

    gcp_parser.add_argument(
        "--report_file",
        "--report-file",
        dest="report_file",
        action="store",
        default="",
        help="Save markdown report",
    )

    gcp_parser.add_argument(
        "-d",
        "--debug",
        dest="debug",
        action="store_true",
        default=False,
        help="Enable debug messages",
    )

    gcp_parser.add_argument(
        "--request_field",
        "--request-field",
        dest="request_field",
        action="store",
        default="",
        help=(
            "Comma separated list of request fields to include in the output."
            "Use `all` to include all fields. If not set, a default request fields will be"
            " included in the output."
        ),
    )

    gcp_parser.add_argument(
        "--response_field",
        "--response-field",
        dest="response_field",
        action="store",
        default="",
        help=(
            "Comma separated list of response fields to include in the output."
            "Use `all` to include all response fields. If not set, a default response fields will"
            " be included in the output."
        ),
    )


def AddAWSParser(subparser):
    """Command line argument for parsing AWS Cloud logs."""
    aws_parser = subparser.add_parser("aws", help="AWS Cloud logs parser.")

    aws_parser.add_argument(
        "--source_file",
        "--source-file",
        dest="source_file",
        action="store",
        default="",
        help="Cloud log as JSONL",
    )

    aws_parser.add_argument(
        "--output_file",
        "--output-file",
        dest="output_file",
        action="store",
        default="",
        help="Timesketch compatible JSONL Cloud log",
    )

    aws_parser.add_argument(
        "--report_file",
        "--report-file",
        dest="report_file",
        action="store",
        default="",
        help="Save markdown report",
    )

    aws_parser.add_argument(
        "-d",
        "--debug",
        dest="debug",
        action="store_true",
        default=False,
        help="Enable debug messages",
    )


def AddAzureParser(subparser):
    """Command line arguments for parsing Azure Cloud logs."""
    azure_parser = subparser.add_parser("azure", help="Azure Cloud logs parser")
    azure_parser.add_argument(
        "--source_file",
        "--source-file",
        dest="source_file",
        action="store",
        default="",
        help="Cloud log as JSONL",
    )

    azure_parser.add_argument(
        "--output_file",
        "--output-file",
        dest="output_file",
        action="store",
        default="",
        help="Timesketch compatible JSONL Cloud log",
    )

    azure_parser.add_argument(
        "--report_file",
        "--report-file",
        dest="report_file",
        action="store",
        default="",
        help="Save markdown report",
    )

    azure_parser.add_argument(
        "-d",
        "--debug",
        dest="debug",
        action="store_true",
        default=False,
        help="Enable debug messages",
    )


def Main():
    """Main entry point to the script."""
    argument_parser = argparse.ArgumentParser(
        description="""\
Process Cloud logs to Timesketch compatible JSONL logs.

The tool takes Cloud logs in JSONL format and returns Timesketch
compatible JSONL output.

        """,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    argument_parser.add_argument(
        "--source_file",
        "--source-file",
        dest="source_file",
        action="store",
        default="",
        help="Cloud log as JSONL",
    )

    argument_parser.add_argument(
        "--output_file",
        "--output-file",
        dest="output_file",
        action="store",
        default="",
        help="Timesketch compatible JSONL Cloud log",
    )

    argument_parser.add_argument(
        "--report_file",
        "--report-file",
        dest="report_file",
        action="store",
        default="",
        help="Save markdown report",
    )

    argument_parser.add_argument(
        "-d",
        "--debug",
        dest="debug",
        action="store_true",
        default=False,
        help="Enable debug messages",
    )

    subparser = argument_parser.add_subparsers(dest="command")
    AddGCPParser(subparser)
    AddAWSParser(subparser)
    AddAzureParser(subparser)

    args = argument_parser.parse_args()

    if not args.source_file:
        print("Source file is missing")
        print("")
        argument_parser.print_help()
        return 1

    if not args.output_file:
        print("Output file is missing")
        print("")
        argument_parser.print_help()
        return 1

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    if args.debug:
        logging.level = logging.DEBUG

    if args.command == "gcp":
        processor = GoogleCloudLog()
        processor.ProcessLogFile(
            args.source_file,
            args.output_file,
            args.report_file,
            args.request_field,
            args.response_field,
        )
    elif args.command == "aws":
        print("AWS support is WIP")
    elif args.command == "azure":
        print("Azure support is WIP")
    else:
        argument_parser.print_help()

    return 0


if __name__ == "__main__":
    sys.exit(Main())
