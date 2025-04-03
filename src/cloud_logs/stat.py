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

"""Cloud logs stats."""

from typing import Any, Dict, List


class GoogleCloudLogStat:
    """Class for tracking Google Cloud audit log stats."""

    def __init__(self, log_source: str) -> None:
        """Initializes GoogleCloudLogStat."""
        self.log_source = log_source
        self.skipped_log_count: int = 0
        self.payload_type_stat: Dict[str, int] = {}
        self.service_stat: Dict[str, int] = {}
        self.method_stat: Dict[str, int] = {}
        self.principal_email_stat: Dict[str, int] = {}

    def UpdateCloudLogStat(self, log_entry: Dict[str, Any]) -> None:
        """Updates GoogleCloudLogStat values using processed log entry."""
        if not log_entry:
            return

        payload_type = log_entry.get("payload_type")
        if payload_type:
            self.payload_type_stat[payload_type] = (
                self.payload_type_stat.get(payload_type, 0) + 1
            )

        service_name = log_entry.get("service_name")
        if service_name:
            self.service_stat[service_name] = self.service_stat.get(service_name, 0) + 1

        method_name = log_entry.get("method_name")
        if method_name:
            self.method_stat[method_name] = self.method_stat.get(method_name, 0) + 1

        principal_email = log_entry.get("principal_email")
        if principal_email:
            self.principal_email_stat[principal_email] = (
                self.principal_email_stat.get(principal_email, 0) + 1
            )

    def IncreaseSkipLogCounter(self) -> None:
        """Increment skip log counter by 1."""
        self.skipped_log_count += 1

    def _CreateMarkdownTable(
        self, attribute_title: str, value_title: str, stat: Dict[str, int]
    ) -> List[str]:
        """Returns markdown table list."""
        md_table = []
        md_table.append(f"| {attribute_title} | {value_title} |")
        md_table.append("|------|------|")

        for attribute, value in stat.items():
            md_table.append(f"| {attribute} | {value} |")

        return md_table

    def Report(self) -> str:
        """Returns GoogleCloudLogStat report."""
        report = []
        report.append("# Google Cloud Audit Logs Stat")
        report.append("")

        report.append(f"Log source: {self.log_source}")
        report.append(f"Skipped logs: {self.skipped_log_count}")
        report.append("")

        report.append("## Payload Stat")
        report.append("")
        report.append("Distribution of Google Cloud logs payload types.")
        report.append("")
        report.extend(
            self._CreateMarkdownTable("Payload Type", "Count", self.payload_type_stat)
        )
        report.append("")

        report.append("## Service Stat")
        report.append("")
        report.append("Distribution of Google Cloud service in logs")
        report.append("")
        report.extend(
            self._CreateMarkdownTable("Service Name", "Count", self.service_stat)
        )
        report.append("")

        report.append("## Method Stat")
        report.append("")
        report.append("Distribution of Google APIs method in logs.")
        report.append("")
        report.extend(
            self._CreateMarkdownTable("Method Name", "Count", self.method_stat)
        )
        report.append("")

        report.append("## Principal Email")
        report.append("")
        report.append("Distribution of principal email that requested APIs.")
        report.append("")
        report.extend(
            self._CreateMarkdownTable(
                "Principal Email", "Count", self.principal_email_stat
            )
        )
        report.append("")

        return "\n".join(report)
