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
"""Gogole Cloud Logs Processor"""

import orjson
import logging
import re

from typing import Any, Dict, List

from cloud_logs.stat import GoogleCloudLogStat


class GoogleCloudLog:
    """Class for processing Google Cloud logs.

    Attributes:
        _log_record (Dict[str, Any]): A dictionary containing data that will be exported to
                Timesketch.
        output_all_request_field (bool): Indicates if all request fields will be added to the
                output.
        request_fields (List[str]): A list of request fields that will be included in the output.
        output_all_response_field (bool): Indicates if all response fields will be added to the
                output.
        response_fields (List[str]): A list of response fields that will be included in the output.
    """

    _USER_AGENT_COMMAND_RE = re.compile(r"command/([^\s]+)")
    _USER_AGENT_INVOCATION_ID_RE = re.compile(r"invocation-id/([^\s]+)")

    def __init__(self) -> None:
        """Initializes GoogleCloudLog."""
        self._log_record = {}
        self.output_all_request_field = False
        self.request_fields = [
            "@type",
            "billingAccountName",
            "name",
        ]
        self.output_all_response_field = False
        self.response_fields = [
            "@type",
            "name",
        ]

    def ServiceName(self) -> str:
        """Returns service name"""
        return self._log_record.get("service_name")

    def AddLogRecord(self, attribute: str, value: Any) -> None:
        """Adds Gogole Cloud log record."""
        if not value:
            return
        self._log_record[attribute] = value

    def AddLogPayloadType(self, payload_type: str) -> None:
        """Adds Google Cloud log payload type."""
        self.AddLogRecord("proto_payload", payload_type)

    def _GetServiceAccountDelegation(
        self, authentication_info: Dict[str, Any]
    ) -> List[str]:
        """Returns service account delegation list."""
        # protoPayload.authenticationInfo.serviceAccountDelegationInfo
        # https://cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog#ServiceAccountDelegationInfo
        delegations = []

        delegation_infos = authentication_info.get("serviceAccountDelegationInfo", [])
        for delegation_info in delegation_infos:
            principal_subject = delegation_info.get("principalSubject")

            first_party_principal = delegation_info.get("firstPartyPrincipal")
            if not first_party_principal:
                delegations.append(principal_subject)
                continue

            first_party_principal_email = first_party_principal.get("principalEmail")
            if first_party_principal_email:
                delegations.append(first_party_principal_email)

        return delegations

    def _ParseAuthenticationInfo(self, payload: Dict[str, Any]) -> None:
        """Parse protoPayload.authenticationInfo."""
        # https://cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog#AuthenticationInfo
        authentication_info = payload.get("authenticationInfo")
        if not authentication_info:
            return None

        self.AddLogRecord("principal_email", authentication_info.get("principalEmail"))
        self.AddLogRecord(
            "principal_subject", authentication_info.get("principalSubject")
        )
        self.AddLogRecord(
            "service_account_key_name", authentication_info.get("serviceAccountKeyName")
        )

        delegations = self._GetServiceAccountDelegation(authentication_info)
        if delegations:
            self.AddLogRecord("delegations", delegations)
            self.AddLogRecord("delegation_chain", "->".join(delegations))

    def _ParseAuthorizationInfo(self, payload: Dict[str, Any]) -> None:
        """Parse protoPayload.authorizationInfo."""
        # protoPayload.authorizationInfo
        # https://cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog#AuthorizationInfo

        # `permissions` contains concatenation of two authorizationInfo attributes
        # `permission` and `permissionType` i.e. `permission`:`permissionType`
        # Example: `compute.project.get:ADMIN_READ`
        authorization_infos = payload.get("authorizationInfo", [])
        if not authorization_infos:
            return None

        permissions = []

        for authorization_info in authorization_infos:
            granted = authorization_info.get("granted", False)
            permission = authorization_info.get("permission")
            permission_type = authorization_info.get("permissionType")

            if permission_type:
                permission = f"{permission}:{permission_type}:{granted}"
            permissions.append(permission)

        self.AddLogRecord("permissions", permissions)

    def _ParseRequestMetadata(self, payload: Dict[str, Any]) -> None:
        """Parse protoPayload.requestMetadata."""
        # protoPayload.requestMetadata
        # https://cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog#RequestMetadata
        request_metadata = payload.get("requestMetadata")
        if not request_metadata:
            return None

        self.AddLogRecord("caller_ip", request_metadata.get("callerIp"))
        self.AddLogRecord("user_agent", request_metadata.get("callerSuppliedUserAgent"))
        self.AddLogRecord("caller_network", request_metadata.get("callerNetwork"))

        user_agent = request_metadata.get("callerSuppliedUserAgent")
        if user_agent:
            if "command/" in user_agent:
                matches = self._USER_AGENT_COMMAND_RE.search(user_agent)
                if matches:
                    command_string = matches.group(1).replace(",", " ")
                    self.AddLogRecord("gcloud_command_partial", command_string)

            if "invocation-id" in user_agent:
                matches = self._USER_AGENT_INVOCATION_ID_RE.search(user_agent)
                if matches:
                    self.AddLogRecord("gcloud_command_identity", matches.group(1))

    def _ParseStatus(self, payload: Dict[str, Any]) -> None:
        """Parse protoPayload.status."""
        # https://cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog#Status
        status = payload.get("status")
        if not status:
            return None

        self.AddLogRecord("status_coode", status.get("code"))
        self.AddLogRecord("status_message", status.get("message"))

        status_reasons = []

        for detail in status.get("details", []):
            reason = detail.get("reason")
            if reason:
                status_reasons.append(reason)
        if status_reasons:
            self.AddLogRecord("status_reasons", status_reasons)

    def _ParseRequest(self, payload: Dict[str, Any]) -> None:
        """Parse protoPayload.request."""
        request = payload.get("request")
        if not request:
            return None

        for key, value in request.items():
            if not self.output_all_request_field:
                if key not in self.request_fields:
                    continue

            if "@" in key:
                key = key.replace("@", "")
            request_key = f"request_{key}"

            self.AddLogRecord(request_key, value)

    def _ParseResponse(self, payload: Dict[str, Any]) -> None:
        """Parse protoPayload.response."""
        response = payload.get("response")
        if not response:
            return None

        for key, value in response.items():
            if not self.output_all_response_field:
                if key not in self.response_fields:
                    continue

            if "@" in key:
                key = key.replace("@", "")
            response_key = f"response_{key}"

            self.AddLogRecord(response_key, value)

    def _ParseServiceData(self, payload: Dict[str, Any]) -> None:
        """Parse protoPayload.serviceData."""
        service_data = payload.get("serviceData")
        if not service_data:
            return None

        # Policy changes
        policy_delta = service_data.get("policyDelta")
        if policy_delta:
            policy_delta_list = []

            for binding_delta in policy_delta.get("bindingDeltas", []):
                action = binding_delta.get("action")
                member = binding_delta.get("member")
                role = binding_delta.get("role")

                policy_delta_list.append(f"{member}:{role}:{action}")
            self.AddLogRecord("policy_deltas", policy_delta_list)

        # Permission changes
        permission_delta = service_data.get("permissionDelta")
        if permission_delta:
            for key, value in permission_delta.items():
                self.AddLogRecord(key, value)

    def _ParseComputeSourceImages(self, request: Dict[str, Any]) -> None:
        """Parse source images."""
        source_images = []

        for disk in request.get("disks", []):
            initialize_params = disk.get("initializeParams", {})

            source_image = initialize_params.get("sourceImage")
            if source_image:
                source_images.append(source_image)
        if source_images:
            self.AddLogRecord("source_images", source_images)

    def _ParseDCSA(self, request: Dict[str, Any]) -> None:
        """Parse request and extract DCSA."""
        dcsa_email = None
        dcsa_scopes = None

        for service_account in request.get("serviceAccounts", []):
            email = service_account.get("email")
            if email:
                dcsa_email = email

            scopes = service_account.get("scopes")
            if scopes:
                if not dcsa_scopes:
                    dcsa_scopes = []

                dcsa_scopes.extend(scopes)

        self.AddLogRecord("dcsa_email", dcsa_email)
        self.AddLogRecord("dcsa_scopes", dcsa_scopes)

    def _ParseComputeAuditLog(self, payload: Dict[str, Any]) -> None:
        """Parse compute.googleapis.com logs."""
        request = payload.get("request")

        # GCE instance create/insert activity
        self._ParseComputeSourceImages(request)
        self._ParseDCSA(request)

    def ProcessProtoPayload(self, payload: Dict[str, Any]) -> None:
        """Process Google Cloud audit protoPayload."""
        # AuditLog or protoPayload attributes
        # https://cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog
        # https://github.com/googleapis/googleapis/blob/master/google/cloud/audit/audit_log.proto
        self.AddLogRecord("service_name", payload.get("serviceName"))
        self.AddLogRecord("method_name", payload.get("methodName"))
        self.AddLogRecord("resource_name", payload.get("resourceName"))

        self._ParseAuthenticationInfo(payload)
        self._ParseAuthorizationInfo(payload)
        self._ParseRequestMetadata(payload)
        self._ParseRequest(payload)
        self._ParseResponse(payload)
        self._ParseServiceData(payload)

        # service specific parsing
        if self.ServiceName() == "compute.googleapis.com":
            self._ParseComputeAuditLog(payload)

    def ProcessJsonPayload(self, payload: Dict[str, Any]) -> None:
        """Process Google Cloud jsonPayload."""
        for key, value in payload.items():
            self.AddLogRecord(key, value)

    def ProcessTextPayload(self, payload: Dict[str, Any]) -> None:
        """Process Google Cloud textPayload."""
        self.AddLogRecord("text_payload", payload)

    def LogRecord(self) -> Dict[str, Any]:
        """Returns processed Google Cloud log entry."""
        if not self._log_record:
            return None
        return self._log_record

    def ProcessLogEntry(self, log_line: str) -> Dict[str, Any]:
        """Process Google Cloud audit log entry."""
        if not log_line:
            return None

        try:
            log_entry = orjson.loads(log_line)
        except orjson.decoder.JSONDecodeError as err:
            logging.debug("Error converting log to JSON. %s", str(err))
            return None

        # Parse LogEntry common attributes.
        self.AddLogRecord("datetime", log_entry.get("timestamp"))
        self.AddLogRecord("timestamp_desc", "Event Recorded")

        self.AddLogRecord("severity", log_entry.get("severity"))
        self.AddLogRecord("log_name", log_entry.get("logName"))

        resource = log_entry.get("resource")
        if resource:
            self.AddLogRecord("resource_type", log_entry.get("type"))

            labels = log_entry.get("labels", {})
            for attribute, value in labels.items():
                self.AddLogRecord(attribute, value)

        # Google Cloug LogEntry is union of:
        # - protoPayload
        # - jsonPayload
        # - textPayload
        proto_payload = log_entry.get("protoPayload")
        json_payload = log_entry.get("jsonPayload")
        text_payload = log_entry.get("textPayload")

        if proto_payload:
            self.AddLogPayloadType("protoPayload")
            self.ProcessProtoPayload(proto_payload)

        if json_payload:
            self.AddLogPayloadType("jsonPayload")
            self.ProcessJsonPayload(json_payload)

        if text_payload:
            self.AddLogPayloadType("textPayload")
            self.ProcessTextPayload(text_payload)

        return self.LogRecord()

    def ProcessLogFile(
        self,
        input_file: str,
        output_file: str,
        report_file: str = None,
        request_field: str = None,
        response_field: str = None,
    ) -> None:
        """Process Google Cloud log JSON (JSON-L) file."""
        log_stat = GoogleCloudLogStat(input_file)

        if request_field:
            if "all" in request_field:
                self.output_all_request_field = True
            else:
                self.request_fields = request_field.split(",")

        if response_field:
            if "all" in response_field:
                self.output_all_response_field = True
            else:
                self.response_fields = response_field.split(",")

        with open(output_file, "w", encoding="utf-8") as output_writer:
            with open(input_file, "r", encoding="utf-8") as input_reader:
                for log_line in input_reader:
                    log_entry = self.ProcessLogEntry(log_line)
                    if not log_entry:
                        log_stat.IncreaseSkipLogCounter()
                        continue

                    output_writer.write(orjson.dumps(log_entry).decode("utf-8"))
                    output_writer.write("\n")

                    if report_file:
                        log_stat.UpdateCloudLogStat(log_entry)

        if report_file:
            with open(report_file, "w", encoding="utf-8") as report_writer:
                report_writer.write(log_stat.Report())
