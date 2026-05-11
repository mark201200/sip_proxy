#!/usr/bin/env python3
import asyncio
import json
import os
import re
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Set, Tuple


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    transport: str = "udp"


@dataclass(frozen=True)
class CancelRoute:
    target: Endpoint
    outbound_branch: str


class SIPMessage:
    def __init__(self, start_line: str, headers: List[str], body: str) -> None:
        self.start_line = start_line
        self.headers = headers
        self.body = body

    @property
    def is_response(self) -> bool:
        parts = self.start_line.split(" ", 2)
        return len(parts) >= 2 and parts[0].endswith("SIP/2.0") and parts[1].isdigit()

    @property
    def method(self) -> str:
        if self.is_response:
            return ""
        return self.start_line.split(" ", 1)[0].strip().upper()

    def get_header(self, name: str) -> Optional[str]:
        name_l = name.lower()
        for line in self.headers:
            if ":" not in line:
                continue
            h, v = line.split(":", 1)
            if h.strip().lower() == name_l:
                return v.strip()
        return None

    def get_headers(self, name: str) -> List[Tuple[int, str]]:
        out: List[Tuple[int, str]] = []
        name_l = name.lower()
        for i, line in enumerate(self.headers):
            if ":" not in line:
                continue
            h, v = line.split(":", 1)
            if h.strip().lower() == name_l:
                out.append((i, v.strip()))
        return out

    def set_header(self, name: str, value: str) -> None:
        idxs = self.get_headers(name)
        if idxs:
            i, _ = idxs[0]
            self.headers[i] = f"{name}: {value}"
            for j, _ in reversed(idxs[1:]):
                self.headers.pop(j)
        else:
            self.headers.append(f"{name}: {value}")

    def remove_header(self, name: str) -> None:
        idxs = self.get_headers(name)
        for i, _ in reversed(idxs):
            self.headers.pop(i)

    def insert_header(self, name: str, value: str, after_names: Optional[List[str]] = None) -> None:
        if not after_names:
            self.headers.insert(0, f"{name}: {value}")
            return

        after_set = {n.lower() for n in after_names}
        insert_at = 0
        for i, line in enumerate(self.headers):
            if ":" not in line:
                continue
            h = line.split(":", 1)[0].strip().lower()
            if h in after_set:
                insert_at = i + 1
        self.headers.insert(insert_at, f"{name}: {value}")

    def to_bytes(self) -> bytes:
        body_bytes = self.body.encode("latin1", errors="replace")
        payload = self.start_line + "\r\n" + "\r\n".join(self.headers) + "\r\n\r\n"
        return payload.encode("latin1", errors="replace") + body_bytes

    @staticmethod
    def parse(data: bytes) -> "SIPMessage":
        text = data.decode("latin1", errors="replace")
        head, sep, body = text.partition("\r\n\r\n")
        if not sep:
            head, sep, body = text.partition("\n\n")
        lines = head.splitlines()
        if not lines:
            raise ValueError("Malformed SIP payload: empty start line")
        start_line = lines[0].strip()
        headers = [line.rstrip("\r") for line in lines[1:]]
        return SIPMessage(start_line, headers, body)


def split_header_uri_list(value: str) -> List[str]:
    parts: List[str] = []
    buf: List[str] = []
    depth = 0
    in_quotes = False
    for ch in value:
        if ch == '"':
            in_quotes = not in_quotes
        elif not in_quotes:
            if ch == "<":
                depth += 1
            elif ch == ">" and depth > 0:
                depth -= 1
            elif ch == "," and depth == 0:
                parts.append("".join(buf).strip())
                buf = []
                continue
        buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())
    return [p for p in parts if p]


def extract_uri(value: str) -> str:
    value = value.strip()
    if "<" in value and ">" in value:
        return value[value.find("<") + 1:value.find(">")].strip()
    return value


def parse_sip_uri(uri: str) -> Tuple[str, int, str, str]:
    raw = extract_uri(uri.strip())
    raw = raw.strip().strip('"').strip("'")

    if raw.lower().startswith("sip:"):
        raw = raw[4:]
    elif raw.lower().startswith("sips:"):
        raw = raw[5:]

    user = ""
    if "@" in raw:
        user, raw = raw.split("@", 1)

    transport = "udp"
    params = ""
    if ";" in raw:
        hostport, params = raw.split(";", 1)
        m = re.search(r"(?:^|;)transport=([^;]+)", params, flags=re.IGNORECASE)
        if m:
            transport = m.group(1).lower()
    else:
        hostport = raw

    hostport = hostport.strip()
    host = hostport
    port = 5060

    # Support IPv6 host form: [addr]:port
    if hostport.startswith("[") and "]" in hostport:
        end = hostport.find("]")
        host = hostport[1:end]
        remainder = hostport[end + 1 :].strip()
        if remainder.startswith(":"):
            p = remainder[1:].strip()
            if p.isdigit():
                port = int(p)
    elif ":" in hostport and hostport.count(":") == 1:
        host, p = hostport.split(":", 1)
        if p.isdigit():
            port = int(p)

    return host.strip().strip("<>").strip('"').strip("'"), port, transport, user.strip()


def split_sip_stream_messages(buffer: bytes) -> Tuple[List[bytes], bytes]:
    messages: List[bytes] = []

    while True:
        sep = b"\r\n\r\n"
        header_end = buffer.find(sep)
        if header_end < 0:
            sep = b"\n\n"
            header_end = buffer.find(sep)
            if header_end < 0:
                break

        head = buffer[:header_end].decode("latin1", errors="replace")
        content_length = 0
        for line in head.splitlines():
            if ":" not in line:
                continue
            h, v = line.split(":", 1)
            if h.strip().lower() == "content-length":
                try:
                    content_length = int(v.strip())
                except ValueError:
                    content_length = 0
                break

        total = header_end + len(sep) + content_length
        if len(buffer) < total:
            break

        messages.append(buffer[:total])
        buffer = buffer[total:]

    return messages, buffer


class SIPProxy:
    def __init__(self) -> None:
        self.listen_ip = os.getenv("SIP_PROXY_LISTEN_IP", "0.0.0.0")
        self.listen_port = int(os.getenv("SIP_PROXY_LISTEN_PORT", "5062"))
        self.api_listen_ip = os.getenv("SIP_PROXY_API_LISTEN_IP", "0.0.0.0")
        self.api_port = int(os.getenv("SIP_PROXY_API_PORT", "8088"))
        self.api_enabled = env_bool("SIP_PROXY_API_ENABLED", True)

        self.pcscf_ip = os.getenv("SIP_PROXY_PCSCF_IP", "")
        self.pcscf_port = int(os.getenv("SIP_PROXY_PCSCF_PORT", "5060"))

        self.default_core_ip = os.getenv("SIP_PROXY_DEFAULT_CORE_IP", "")
        self.default_core_port = int(os.getenv("SIP_PROXY_DEFAULT_CORE_PORT", "4060"))

        self.advertised_host = os.getenv("SIP_PROXY_ADVERTISED_HOST", self.listen_ip)
        self.route_user = os.getenv("SIP_PROXY_ROUTE_USER", "sipproxy")

        self.log_messages = env_bool("SIP_PROXY_LOG_MESSAGES", False)
        self.insert_record_route = env_bool("SIP_PROXY_INSERT_RECORD_ROUTE", True)
        self.allow_unsafe_live_invite_sdp_rewrite = env_bool(
            "SIP_PROXY_ALLOW_UNSAFE_LIVE_INVITE_SDP_REWRITE",
            False,
        )

        rewrite_json = os.getenv("SIP_PROXY_REWRITE_RULES", "[]")
        try:
            parsed_rules = json.loads(rewrite_json)
            if not isinstance(parsed_rules, list):
                parsed_rules = []
        except json.JSONDecodeError:
            parsed_rules = []
        self.rewrite_rules = self._normalize_rewrite_rules(parsed_rules)

        self.transactions: Dict[str, Endpoint] = {}
        self.transaction_upstream_vias: Dict[str, List[str]] = {}
        self.cancel_routes: Dict[str, CancelRoute] = {}
        self.tester_transaction_correlation: Dict[str, str] = {}
        self.tester_transaction_device_host: Dict[str, str] = {}
        self.tester_responses: Dict[str, List[str]] = {}
        self.tester_response_events: Dict[str, asyncio.Event] = {}
        self.tester_max_buffered_responses = int(os.getenv("SIP_PROXY_TESTER_MAX_BUFFERED_RESPONSES", "32"))
        self.tester_route_via_pcscf = env_bool("SIP_PROXY_TESTER_ROUTE_VIA_PCSCF", True)
        self.discovered_register_devices: Dict[str, Dict[str, Any]] = {}
        self.discovered_register_max_entries = int(
            os.getenv("SIP_PROXY_DISCOVERED_REGISTER_MAX_ENTRIES", "512")
        )

        self.live_edit_hit_sequence = 0
        self.live_edit_hits: List[Dict[str, Any]] = []
        self.live_edit_hit_event = asyncio.Event()
        self.live_edit_max_buffered_hits = int(os.getenv("SIP_PROXY_LIVE_EDIT_MAX_BUFFERED_HITS", "256"))
        self.live_edit_guard_logged_rules: Set[str] = set()

        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.udp_transport = None
        self.tcp_server: Optional[asyncio.AbstractServer] = None

    def _log(self, msg: str) -> None:
        print(f"[sip-proxy] {msg}", flush=True)

    def _is_from_pcscf(self, src_host: str) -> bool:
        return bool(self.pcscf_ip) and src_host == self.pcscf_ip

    def _extract_branch(self, via_value: str) -> Optional[str]:
        m = re.search(r"(?:^|;)branch=([^;\s]+)", via_value, flags=re.IGNORECASE)
        return m.group(1) if m else None

    def _transaction_key(self, branch: str, cseq: str) -> str:
        return f"{branch}|{cseq.strip()}"

    def _cancel_route_key(self, src_host: str, inbound_branch: str, call_id: str, cseq_num: str) -> str:
        return f"{src_host}|{inbound_branch}|{call_id.strip()}|{cseq_num.strip()}"

    def _parse_cseq(self, cseq: str) -> Tuple[str, str]:
        parts = cseq.strip().split()
        if len(parts) < 2:
            return "", ""
        return parts[0], parts[1].upper()

    def _is_our_via(self, via_value: str) -> bool:
        m = re.match(r"^\s*SIP/2\.0/[A-Za-z]+\s+([^;]+)", via_value)
        if not m:
            return False

        sent_by = m.group(1).strip()
        host = sent_by
        port = 5060

        if sent_by.startswith("[") and "]" in sent_by:
            end = sent_by.find("]")
            host = sent_by[1:end]
            remainder = sent_by[end + 1 :].strip()
            if remainder.startswith(":") and remainder[1:].isdigit():
                port = int(remainder[1:])
        elif ":" in sent_by and sent_by.count(":") == 1:
            host, p = sent_by.split(":", 1)
            if p.isdigit():
                port = int(p)

        known_hosts = {self.advertised_host.lower(), self.listen_ip.lower(), socket.gethostname().lower()}
        return port == self.listen_port and host.lower() in known_hosts

    def _extract_via_host(self, via_value: str) -> str:
        m = re.match(r"^\s*SIP/2\.0/[A-Za-z]+\s+([^;]+)", via_value)
        if not m:
            return ""

        sent_by = m.group(1).strip()
        host = sent_by
        if sent_by.startswith("[") and "]" in sent_by:
            host = sent_by[1 : sent_by.find("]")]
        elif ":" in sent_by and sent_by.count(":") == 1:
            host = sent_by.split(":", 1)[0]

        return self._normalize_host_for_match(host)

    def _response_contains_device_via(self, msg: SIPMessage, expected_host: str) -> bool:
        if not expected_host:
            return False

        for via_value in self._via_values(msg):
            if self._extract_via_host(via_value) == expected_host:
                return True
        return False

    def _message_contains_device_host(self, msg: SIPMessage, expected_host: str) -> bool:
        if not expected_host:
            return False

        candidate_headers = [
            "Contact",
            "From",
            "To",
            "P-Preferred-Identity",
            "P-Asserted-Identity",
            "Record-Route",
            "Route",
        ]
        for header_name in candidate_headers:
            for _, raw_value in msg.get_headers(header_name):
                for uri_candidate in split_header_uri_list(raw_value):
                    uri_value = extract_uri(uri_candidate)
                    host, _, _, _ = parse_sip_uri(uri_value)
                    if self._normalize_host_for_match(host) == expected_host:
                        return True
        return False

    def _response_matches_selected_device(self, msg: SIPMessage, src: Endpoint, expected_host: str) -> bool:
        if not expected_host:
            return False

        normalized_src = self._normalize_host_for_match(src.host)
        if normalized_src == expected_host:
            return True

        if self._response_contains_device_via(msg, expected_host):
            return True

        if self._message_contains_device_host(msg, expected_host):
            return True

        return False

    def _via_values(self, msg: SIPMessage) -> List[str]:
        values: List[str] = []
        for line in msg.headers:
            if ":" not in line:
                continue
            h, v = line.split(":", 1)
            if h.strip().lower() in {"via", "v"}:
                values.append(v.strip())
        return values

    def _replace_vias(self, msg: SIPMessage, via_values: List[str]) -> None:
        msg.remove_header("Via")
        msg.remove_header("v")
        for via_value in reversed(via_values):
            msg.insert_header("Via", via_value)

    def _sanitize_rule_direction(self, value: Any) -> str:
        direction = str(value or "any").strip().lower()
        if direction in {"request", "response", "any"}:
            return direction
        return "any"

    def _sanitize_rule_method(self, value: Any) -> str:
        method = str(value or "*").strip().upper()
        if not method or method == "ANY":
            return "*"
        return method

    def _sanitize_rule_device_scope(self, value: Any) -> str:
        scope = str(value or "either").strip().lower()
        if scope in {"source", "destination", "either"}:
            return scope
        return "either"

    def _device_scope_for_direction(self, direction: str) -> str:
        normalized_direction = self._sanitize_rule_direction(direction)
        if normalized_direction == "request":
            return "source"
        if normalized_direction == "response":
            return "destination"
        return "either"

    @staticmethod
    def _normalize_host_for_match(value: Any) -> str:
        candidate = str(value or "").strip().lower()
        if not candidate:
            return ""

        if candidate.startswith("[") and candidate.endswith("]"):
            candidate = candidate[1:-1].strip()

        return candidate

    def _endpoint_host_matches(self, endpoint: Optional[Endpoint], expected_host: str) -> bool:
        if endpoint is None:
            return False
        return self._normalize_host_for_match(endpoint.host) == expected_host

    def _header_identity_candidates(self, msg: SIPMessage, header_names: List[str]) -> Set[str]:
        candidates: Set[str] = set()
        for header_name in header_names:
            value = msg.get_header(header_name)
            if not value:
                continue
            for identity in self._extract_normalized_identities_from_uri_value(value):
                if identity:
                    candidates.add(identity)
        return candidates

    def _message_identity_candidates(self, msg: SIPMessage, scope: str = "either") -> Set[str]:
        normalized_scope = self._sanitize_rule_device_scope(scope)

        if msg.is_response:
            # SIP responses keep From/To from the original request:
            # To identifies the responder side, From identifies the requester side.
            source_candidates = self._header_identity_candidates(
                msg,
                ["P-Preferred-Identity", "P-Asserted-Identity", "To", "Contact"],
            )
            destination_candidates = self._header_identity_candidates(msg, ["From"])
        else:
            source_candidates = self._header_identity_candidates(
                msg,
                ["P-Preferred-Identity", "P-Asserted-Identity", "From", "Contact"],
            )
            destination_candidates = self._header_identity_candidates(msg, ["To"])

            request_uri = self._request_uri_from_message(msg)
            if request_uri:
                for identity in self._extract_normalized_identities_from_uri_value(request_uri):
                    if identity:
                        destination_candidates.add(identity)

        if normalized_scope == "source":
            return source_candidates
        if normalized_scope == "destination":
            return destination_candidates
        return source_candidates | destination_candidates

    @staticmethod
    def _canonicalize_identity_values(values: Set[str]) -> Set[str]:
        canonical: Set[str] = set()
        for value in values:
            candidate = str(value or "").strip()
            if not candidate:
                continue
            if candidate.startswith("+"):
                candidate = candidate[1:]
            canonical.add(candidate)
        return canonical

    def _identity_matches_scope(self, msg: SIPMessage, expected_identities: Set[str], scope: str) -> bool:
        normalized_scope = self._sanitize_rule_device_scope(scope)
        canonical_expected = self._canonicalize_identity_values(expected_identities)
        if not canonical_expected:
            return False

        canonical_source = self._canonicalize_identity_values(
            self._message_identity_candidates(msg, "source")
        )
        canonical_destination = self._canonicalize_identity_values(
            self._message_identity_candidates(msg, "destination")
        )

        source_match = bool(canonical_source & canonical_expected)
        destination_match = bool(canonical_destination & canonical_expected)

        if normalized_scope == "source":
            if source_match != destination_match:
                return source_match
            if source_match and destination_match:
                # Symmetric identities (e.g. REGISTER From==To) are ambiguous.
                # Fall back to SIP class: request means sent, response means received.
                return not msg.is_response
            return False

        if normalized_scope == "destination":
            if source_match != destination_match:
                return destination_match
            if source_match and destination_match:
                # Symmetric identities (e.g. REGISTER From==To) are ambiguous.
                # Fall back to SIP class: response means received, request means sent.
                return msg.is_response
            return False

        return source_match or destination_match

    def _normalize_rewrite_rule(self, rule: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(rule, dict):
            return None

        normalized: Dict[str, Any] = {
            "id": str(rule.get("id") or uuid.uuid4().hex),
            "enabled": bool(rule.get("enabled", True)),
            "direction": self._sanitize_rule_direction(rule.get("direction", "any")),
            "method": self._sanitize_rule_method(rule.get("method", "*")),
        }

        device_host = self._normalize_host_for_match(rule.get("device_host", ""))
        if device_host:
            normalized["device_host"] = device_host
            normalized["device_scope"] = self._sanitize_rule_device_scope(rule.get("device_scope", "either"))

        device_phone_number = self._normalize_phone_number(str(rule.get("device_phone_number", "")))
        if device_phone_number:
            normalized["device_phone_number"] = device_phone_number

        device_imsi = str(rule.get("device_imsi", "")).strip()
        if device_imsi:
            normalized["device_imsi"] = device_imsi

        action = str(rule.get("action", "")).strip().lower()
        has_pattern = isinstance(rule.get("pattern"), str) and bool(str(rule.get("pattern")))

        if not action:
            if has_pattern:
                action = "regex-replace"
            elif rule.get("header") is not None and rule.get("value") is not None:
                action = "set-header"

        if action == "regex-replace":
            pattern = str(rule.get("pattern", ""))
            if not pattern:
                return None
            normalized["action"] = "regex-replace"
            normalized["pattern"] = pattern
            normalized["replace"] = str(rule.get("replace", ""))
            return normalized

        if action == "set-header":
            header = str(rule.get("header", "")).strip()
            if not header:
                return None
            normalized["action"] = "set-header"
            normalized["header"] = header
            normalized["value"] = str(rule.get("value", ""))
            return normalized

        if action == "remove-header":
            header = str(rule.get("header", "")).strip()
            if not header:
                return None
            normalized["action"] = "remove-header"
            normalized["header"] = header
            return normalized

        if action == "set-start-line":
            normalized["action"] = "set-start-line"
            normalized["value"] = str(rule.get("value", ""))
            return normalized

        if action == "set-body":
            normalized["action"] = "set-body"
            normalized["value"] = str(rule.get("value", ""))
            return normalized

        return None

    def _normalize_rewrite_rules(self, rules: List[Any]) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        for rule in rules:
            out = self._normalize_rewrite_rule(rule)
            if out is not None:
                normalized.append(out)
        return normalized

    def _rule_matches_message(
        self,
        rule: Dict[str, Any],
        msg: SIPMessage,
        src: Optional[Endpoint] = None,
        dst: Optional[Endpoint] = None,
    ) -> bool:
        if not bool(rule.get("enabled", True)):
            return False

        method_filter = str(rule.get("method", "*")).upper()
        if method_filter in {"*", "ANY", ""}:
            method_matches = True
        elif msg.is_response:
            cseq = msg.get_header("CSeq") or ""
            _, cseq_method = self._parse_cseq(cseq)
            method_matches = cseq_method == method_filter
        else:
            method_matches = msg.method == method_filter

        if not method_matches:
            return False

        direction = self._sanitize_rule_direction(rule.get("direction", "any"))
        device_host = self._normalize_host_for_match(rule.get("device_host", ""))
        device_phone_number = self._normalize_phone_number(str(rule.get("device_phone_number", "")))
        device_imsi = str(rule.get("device_imsi", "")).strip()

        host_filter_present = bool(device_host)
        identity_filter_present = bool(device_phone_number or device_imsi)
        has_device_filter = host_filter_present or identity_filter_present

        # Backward compatibility for non-device-scoped rules:
        # request/response refers to SIP message class.
        if not has_device_filter:
            if msg.is_response and direction == "request":
                return False
            if not msg.is_response and direction == "response":
                return False

        scope = self._sanitize_rule_device_scope(
            rule.get("device_scope", self._device_scope_for_direction(direction))
        )

        host_matches = False
        if host_filter_present:
            source_matches = self._endpoint_host_matches(src, device_host)
            destination_matches = self._endpoint_host_matches(dst, device_host)

            if scope == "source":
                host_matches = source_matches
            elif scope == "destination":
                host_matches = destination_matches
            else:
                host_matches = source_matches or destination_matches

        identity_matches = False
        if identity_filter_present:
            expected_identities: Set[str] = set()
            if device_phone_number:
                expected_identities.add(device_phone_number)
            if device_imsi:
                expected_identities.add(device_imsi)

            # INVITE traffic often carries only one of phone/imsi on each hop.
            # Scope-aware identity matching keeps selected-device direction semantics.
            identity_matches = self._identity_matches_scope(msg, expected_identities, scope)

        if host_filter_present and identity_filter_present:
            return host_matches or identity_matches

        if host_filter_present:
            return host_matches

        if identity_filter_present:
            return identity_matches

        return True

    def _apply_regex_rewrite(self, msg: SIPMessage, rule: Dict[str, Any]) -> None:
        pattern = str(rule.get("pattern", ""))
        replace = str(rule.get("replace", ""))
        if not pattern:
            return

        raw = msg.start_line + "\r\n" + "\r\n".join(msg.headers) + "\r\n\r\n" + msg.body
        try:
            rewritten = re.sub(pattern, replace, raw)
            reparsed = SIPMessage.parse(rewritten.encode("latin1", errors="replace"))
        except re.error as exc:
            self._log(f"Skipping invalid regex rewrite rule {rule.get('id', '')}: {exc}")
            return
        except Exception as exc:
            self._log(f"Skipping malformed regex rewrite result for rule {rule.get('id', '')}: {exc}")
            return

        msg.start_line = reparsed.start_line
        msg.headers = reparsed.headers
        msg.body = reparsed.body

    def _message_looks_like_sdp_offer_or_answer(self, msg: SIPMessage) -> bool:
        body = msg.body
        if not body:
            return False

        compact = body.lstrip()
        if not compact.startswith("v="):
            return False

        return "\nm=" in compact or "\r\nm=" in compact

    def _is_invite_response(self, msg: SIPMessage) -> bool:
        if not msg.is_response:
            return False

        cseq = msg.get_header("CSeq") or ""
        _, cseq_method = self._parse_cseq(cseq)
        return cseq_method == "INVITE"

    def _header_has_non_sdp_content_type(self, msg: SIPMessage) -> bool:
        content_type = msg.get_header("Content-Type")
        if content_type is None:
            return True
        return "application/sdp" not in content_type.lower()

    def _remove_option_tag(self, msg: SIPMessage, header_name: str, option_tag: str) -> None:
        matches = msg.get_headers(header_name)
        if not matches:
            return

        wanted = option_tag.lower().strip()
        kept_values: List[str] = []
        for _, raw_value in matches:
            tokens = [token.strip() for token in raw_value.split(",") if token.strip()]
            filtered = [token for token in tokens if token.lower() != wanted]
            if filtered:
                kept_values.append(",".join(filtered))

        msg.remove_header(header_name)
        if not kept_values:
            return

        for value in reversed(kept_values):
            msg.insert_header(header_name, value)

    def _mitigate_100rel_for_live_invite_content_type_fuzz(self, msg: SIPMessage) -> None:
        if msg.is_response or msg.method != "INVITE":
            return

        # Tester-injected vectors should remain byte-for-byte controllable.
        if msg.get_header("X-IMS-Tester-Correlation-ID"):
            return

        if not self._message_looks_like_sdp_offer_or_answer(msg):
            return

        if not self._header_has_non_sdp_content_type(msg):
            return

        # Avoid triggering reliable early-offer flow (PRACK with mandatory SDP answer),
        # which many handsets reject in this malformed Content-Type scenario.
        self._remove_option_tag(msg, "Supported", "100rel")
        self._remove_option_tag(msg, "Require", "100rel")
        self._remove_option_tag(msg, "Proxy-Require", "100rel")

    def _rule_is_unsafe_for_live_invite_sdp(self, msg: SIPMessage, rule: Dict[str, Any]) -> bool:
        if self.allow_unsafe_live_invite_sdp_rewrite:
            return False

        # Tester-injected traffic intentionally fuzzes malformed SIP vectors.
        if msg.get_header("X-IMS-Tester-Correlation-ID"):
            return False

        action = str(rule.get("action", "")).strip().lower()
        if action not in {"set-header", "remove-header"}:
            return False

        header_name = str(rule.get("header", "")).strip().lower()
        if header_name not in {"content-type", "content-length"}:
            return False

        # INVITE responses with SDP are sensitive for PRACK/offer-answer handling.
        if self._is_invite_response(msg) and self._message_looks_like_sdp_offer_or_answer(msg):
            return True

        # Keep malformed request Content-Length vectors opt-in for live traffic.
        if (not msg.is_response) and msg.method == "INVITE" and header_name == "content-length":
            return True

        return False

    def _log_live_invite_sdp_guard(self, rule: Dict[str, Any]) -> None:
        rule_id = str(rule.get("id", "")).strip() or "(no-id)"
        if rule_id in self.live_edit_guard_logged_rules:
            return

        self.live_edit_guard_logged_rules.add(rule_id)
        self._log(
            "Skipping unsafe live INVITE rewrite for rule "
            f"{rule_id}. Set SIP_PROXY_ALLOW_UNSAFE_LIVE_INVITE_SDP_REWRITE=true "
            "to force it."
        )

    def _apply_rewrites(
        self,
        msg: SIPMessage,
        src: Optional[Endpoint] = None,
        dst: Optional[Endpoint] = None,
    ) -> None:
        if not self.rewrite_rules:
            return

        for rule in self.rewrite_rules:
            if not self._rule_matches_message(rule, msg, src=src, dst=dst):
                continue

            if self._rule_is_unsafe_for_live_invite_sdp(msg, rule):
                self._log_live_invite_sdp_guard(rule)
                continue

            self._record_live_edit_hit(rule, msg, src=src, dst=dst)

            action = str(rule.get("action", "")).strip().lower()
            if action == "regex-replace":
                self._apply_regex_rewrite(msg, rule)
                continue

            if action == "set-header":
                msg.set_header(str(rule.get("header", "")), str(rule.get("value", "")))
                continue

            if action == "remove-header":
                msg.remove_header(str(rule.get("header", "")))
                continue

            if action == "set-start-line":
                msg.start_line = str(rule.get("value", ""))
                continue

            if action == "set-body":
                msg.body = str(rule.get("value", ""))

        self._mitigate_100rel_for_live_invite_content_type_fuzz(msg)

    def _predict_response_target(self, msg: SIPMessage, src: Endpoint) -> Optional[Endpoint]:
        vias = msg.get_headers("Via")
        if not vias:
            return None

        _, top_via_val = vias[0]
        branch = self._extract_branch(top_via_val) or ""
        cseq = msg.get_header("CSeq") or ""
        key = self._transaction_key(branch, cseq)

        target = self.transactions.get(key)
        if target is not None:
            return target

        if self._is_from_pcscf(src.host):
            return Endpoint(self.default_core_ip, self.default_core_port, "udp")

        return Endpoint(self.pcscf_ip, self.pcscf_port, "udp")

    def _pop_proxy_route_if_needed(self, msg: SIPMessage) -> None:
        routes = msg.get_headers("Route")
        if not routes:
            return

        i, route_value = routes[0]
        entries = split_header_uri_list(route_value)
        if not entries:
            return

        first_uri = extract_uri(entries[0])
        host, port, _, user = parse_sip_uri(first_uri)
        host_match = host in {self.advertised_host, self.listen_ip, socket.gethostname()}
        if host_match and port == self.listen_port and (not user or user == self.route_user):
            entries = entries[1:]
            if entries:
                msg.headers[i] = "Route: " + ", ".join(entries)
            else:
                msg.headers.pop(i)

    def _determine_target_from_header(self, msg: SIPMessage) -> Optional[Endpoint]:
        target = msg.get_header("X-SIP-Proxy-Target")
        if not target:
            return None
        msg.remove_header("X-SIP-Proxy-Target")

        # Header may contain a name-addr or a comma-separated list; use the first URI.
        entries = split_header_uri_list(target)
        target_uri = extract_uri(entries[0]) if entries else extract_uri(target)

        host, port, transport, _ = parse_sip_uri(target_uri)
        if not host:
            return None

        # Some P-CSCF templates can forward unresolved placeholders (e.g. icscf.IMS_DOMAIN).
        # Fall back to configured core IP to keep routing deterministic.
        if self.default_core_ip and "IMS_DOMAIN" in host.upper():
            host = self.default_core_ip
        return Endpoint(host=host, port=port, transport=transport)

    async def _send_udp(self, data: bytes, target: Endpoint) -> None:
        if not self.udp_transport:
            raise RuntimeError("UDP transport is not ready")
        self.udp_transport.sendto(data, (target.host, target.port))

    async def _send_tcp(self, data: bytes, target: Endpoint) -> None:
        writer: Optional[asyncio.StreamWriter] = None
        try:
            _, writer = await asyncio.open_connection(target.host, target.port)
            writer.write(data)
            await writer.drain()
        except socket.gaierror as exc:
            # Keep proxy transparent: if name resolution fails, fallback to core IP.
            if self.default_core_ip and target.host != self.default_core_ip:
                self._log(
                    f"DNS resolution failed for target {target.host}:{target.port} ({exc}); "
                    f"retrying via {self.default_core_ip}:{target.port}"
                )
                _, writer = await asyncio.open_connection(self.default_core_ip, target.port)
                writer.write(data)
                await writer.drain()
            else:
                raise
        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()

    async def _send(self, data: bytes, target: Endpoint) -> None:
        if target.transport.lower() == "tcp":
            await self._send_tcp(data, target)
        else:
            await self._send_udp(data, Endpoint(target.host, target.port, "udp"))

    def _format_target_uri(self, target: Endpoint) -> str:
        transport = (target.transport or "udp").lower()
        return f"<sip:{target.host}:{target.port};transport={transport}>"

    def _extract_status_code(self, start_line: str) -> int:
        parts = start_line.strip().split(" ", 2)
        if len(parts) < 2:
            return 0
        if not parts[1].isdigit():
            return 0
        return int(parts[1])

    @staticmethod
    def _now_utc_iso() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _looks_like_ip_literal(host: str) -> bool:
        candidate = host.strip().strip("[]")
        if not candidate:
            return False
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                socket.inet_pton(family, candidate)
                return True
            except OSError:
                continue
        return False

    @staticmethod
    def _normalize_phone_number(value: str) -> str:
        candidate = (value or "").strip()
        if not candidate:
            return ""

        if candidate.lower().startswith("tel:"):
            candidate = candidate[4:]

        if ";" in candidate:
            candidate = candidate.split(";", 1)[0]

        if candidate.startswith("+"):
            digits = re.sub(r"\D", "", candidate[1:])
            return f"+{digits}" if digits else ""

        return re.sub(r"\D", "", candidate)

    @staticmethod
    def _is_probable_imsi(value: str) -> bool:
        candidate = (value or "").strip()
        return candidate.isdigit() and 14 <= len(candidate) <= 16

    def _is_probable_phone_number(self, value: str) -> bool:
        candidate = (value or "").strip()
        if not candidate:
            return False

        digits = re.sub(r"\D", "", candidate)
        if not digits:
            return False

        # E.164-like numbers are accepted when explicitly marked with '+'
        # while bare long numeric identifiers are treated as likely IMSI.
        if candidate.startswith("+"):
            return 6 <= len(digits) <= 15

        if self._is_probable_imsi(candidate):
            return False

        return 6 <= len(digits) <= 13

    @staticmethod
    def _request_uri_from_message(msg: SIPMessage) -> str:
        if msg.is_response:
            return ""
        parts = msg.start_line.strip().split(" ", 2)
        if len(parts) < 2:
            return ""
        return parts[1].strip()

    def _extract_normalized_identities_from_uri_value(self, header_value: str) -> List[str]:
        entries = split_header_uri_list(header_value)
        if not entries:
            entries = [header_value]

        identities: List[str] = []

        for entry in entries:
            uri = extract_uri(entry).strip()
            if not uri or uri == "*":
                continue

            if uri.lower().startswith("tel:"):
                normalized = self._normalize_phone_number(uri)
                if normalized:
                    identities.append(normalized)
                continue

            try:
                _, _, _, user = parse_sip_uri(uri)
            except Exception:
                continue

            normalized = self._normalize_phone_number(user)
            if normalized:
                identities.append(normalized)

        unique_identities: List[str] = []
        seen: Set[str] = set()
        for identity in identities:
            if identity in seen:
                continue
            seen.add(identity)
            unique_identities.append(identity)

        return unique_identities

    def _extract_subscriber_identities(self, msg: SIPMessage) -> Tuple[str, str]:
        candidates: List[str] = []
        for header_name in [
            "P-Preferred-Identity",
            "P-Asserted-Identity",
            "From",
            "To",
            "Contact",
        ]:
            value = msg.get_header(header_name)
            if not value:
                continue
            candidates.extend(self._extract_normalized_identities_from_uri_value(value))

        request_uri = self._request_uri_from_message(msg)
        if request_uri:
            candidates.extend(self._extract_normalized_identities_from_uri_value(request_uri))

        phone_number = ""
        imsi = ""
        for candidate in candidates:
            if not phone_number and self._is_probable_phone_number(candidate):
                phone_number = candidate
            if not imsi and self._is_probable_imsi(candidate):
                imsi = candidate
            if phone_number and imsi:
                break

        if not phone_number:
            for candidate in candidates:
                if not self._is_probable_imsi(candidate):
                    phone_number = candidate
                    break

        if not imsi:
            for candidate in candidates:
                if self._is_probable_imsi(candidate):
                    imsi = candidate
                    break

        return phone_number, imsi

    def _extract_register_contact_uri(self, msg: SIPMessage) -> str:
        contact_value = msg.get_header("Contact")
        if not contact_value:
            return ""

        entries = split_header_uri_list(contact_value)
        if not entries:
            entries = [contact_value]

        for entry in entries:
            uri = extract_uri(entry).strip()
            if uri and uri != "*":
                return uri

        return ""

    @staticmethod
    def _extract_expires_value(raw_value: str) -> Optional[int]:
        candidate = (raw_value or "").strip().strip('"').strip("'")
        if not candidate:
            return None

        match = re.match(r"^[-+]?\d+$", candidate)
        if not match:
            return None

        try:
            return int(candidate)
        except ValueError:
            return None

    def _register_indicates_deregistration(self, msg: SIPMessage) -> bool:
        expires_header = msg.get_header("Expires")
        expires_value = self._extract_expires_value(expires_header or "")
        if expires_value is not None and expires_value <= 0:
            return True

        contact_value = msg.get_header("Contact")
        if not contact_value:
            return False

        entries = split_header_uri_list(contact_value)
        if not entries:
            entries = [contact_value]

        contact_expires_values: List[int] = []
        for entry in entries:
            match = re.search(r"(?:^|;)\s*expires\s*=\s*([^;\s]+)", entry, flags=re.IGNORECASE)
            if not match:
                continue
            parsed = self._extract_expires_value(match.group(1))
            if parsed is not None:
                contact_expires_values.append(parsed)

        return bool(contact_expires_values) and all(value <= 0 for value in contact_expires_values)

    def _remove_discovered_register_devices(
        self,
        phone_number: str,
        imsi: str,
        ip_address: str,
        contact_uri: str,
        aor: str,
    ) -> int:
        normalized_phone = phone_number.strip()
        normalized_imsi = imsi.strip()
        normalized_ip = ip_address.strip()
        normalized_contact = contact_uri.strip()
        normalized_aor = aor.strip()

        if not any([normalized_phone, normalized_imsi, normalized_ip, normalized_contact, normalized_aor]):
            return 0

        stale_keys: List[str] = []
        for key, record in self.discovered_register_devices.items():
            metadata = record.get("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}

            record_phone = str(metadata.get("phone_number", "")).strip()
            record_imsi = str(metadata.get("imsi", "")).strip()
            record_ip = str(record.get("address", "")).strip()
            record_contact = str(metadata.get("contact_uri", "")).strip()
            record_aor = str(metadata.get("aor", "")).strip()

            if normalized_phone and record_phone != normalized_phone:
                continue
            if normalized_imsi and record_imsi != normalized_imsi:
                continue
            if normalized_ip and record_ip != normalized_ip:
                continue
            if normalized_contact and record_contact != normalized_contact:
                continue
            if normalized_aor and record_aor != normalized_aor:
                continue

            stale_keys.append(key)

        for key in stale_keys:
            self.discovered_register_devices.pop(key, None)

        return len(stale_keys)

    def _extract_ip_from_uri(self, uri: str) -> str:
        if not uri:
            return ""

        try:
            host, _, _, _ = parse_sip_uri(uri)
        except Exception:
            return ""

        host = host.strip().strip("[]")
        if self._looks_like_ip_literal(host):
            return host
        return ""

    @staticmethod
    def _slugify_device_token(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")

    def _build_discovered_device_id(self, phone_number: str, ip_address: str) -> str:
        phone_token = self._slugify_device_token(phone_number)
        ip_token = self._slugify_device_token(ip_address.replace(":", "-"))

        if phone_token and ip_token:
            return f"auto-{phone_token}-{ip_token}"
        if phone_token:
            return f"auto-{phone_token}"
        if ip_token:
            return f"auto-{ip_token}"
        return f"auto-{uuid.uuid4().hex[:8]}"

    @staticmethod
    def _build_discovered_device_name(phone_number: str, ip_address: str) -> str:
        if phone_number and ip_address:
            return f"{phone_number} ({ip_address})"
        if phone_number:
            return phone_number
        if ip_address:
            return ip_address
        return "Discovered Device"

    @staticmethod
    def _build_discovered_device_key(
        phone_number: str,
        ip_address: str,
        contact_uri: str,
        aor: str,
    ) -> str:
        if phone_number and ip_address:
            return f"{phone_number}|{ip_address}"
        if phone_number:
            return f"{phone_number}|"
        if ip_address:
            return f"|{ip_address}"
        if contact_uri:
            return f"contact|{contact_uri}"
        if aor:
            return f"aor|{aor}"
        return ""

    def _record_register_discovery(self, msg: SIPMessage, src: Endpoint) -> None:
        phone_number, imsi = self._extract_subscriber_identities(msg)
        contact_uri = self._extract_register_contact_uri(msg)
        ip_address = self._extract_ip_from_uri(contact_uri)

        aor_header_value = msg.get_header("To") or msg.get_header("From") or ""
        aor_value = extract_uri(aor_header_value).strip() if aor_header_value else ""

        if self._register_indicates_deregistration(msg):
            self._remove_discovered_register_devices(
                phone_number=phone_number,
                imsi=imsi,
                ip_address=ip_address,
                contact_uri=contact_uri,
                aor=aor_value,
            )
            return

        if not ip_address and not self._is_from_pcscf(src.host) and self._looks_like_ip_literal(src.host):
            ip_address = src.host.strip()

        if not ip_address:
            return

        self._upsert_discovered_device(
            phone_number=phone_number,
            imsi=imsi,
            ip_address=ip_address,
            contact_uri=contact_uri,
            aor_value=aor_value,
            user_agent=(msg.get_header("User-Agent") or "").strip(),
            src=src,
            register_hint=True,
            subscribe_hint=False,
        )

    def _record_subscribe_identity_hint(self, msg: SIPMessage, src: Endpoint) -> None:
        phone_number, imsi = self._extract_subscriber_identities(msg)
        if not phone_number and not imsi:
            return

        contact_uri = self._extract_register_contact_uri(msg)
        ip_address = self._extract_ip_from_uri(contact_uri)

        if not ip_address and not self._is_from_pcscf(src.host) and self._looks_like_ip_literal(src.host):
            ip_address = src.host.strip()

        aor_header_value = msg.get_header("To") or msg.get_header("From") or ""
        aor_value = extract_uri(aor_header_value).strip() if aor_header_value else ""

        self._upsert_discovered_device(
            phone_number=phone_number,
            imsi=imsi,
            ip_address=ip_address,
            contact_uri=contact_uri,
            aor_value=aor_value,
            user_agent=(msg.get_header("User-Agent") or "").strip(),
            src=src,
            register_hint=False,
            subscribe_hint=True,
        )

    def _find_existing_discovered_key(
        self,
        phone_number: str,
        imsi: str,
        ip_address: str,
        contact_uri: str,
        aor_value: str,
    ) -> str:
        preferred_key = self._build_discovered_device_key(phone_number, ip_address, contact_uri, aor_value)
        if preferred_key and preferred_key in self.discovered_register_devices:
            return preferred_key

        if ip_address:
            for key, record in self.discovered_register_devices.items():
                if str(record.get("address", "")).strip() == ip_address:
                    return key

        for key, record in self.discovered_register_devices.items():
            metadata = record.get("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}

            if contact_uri and str(metadata.get("contact_uri", "")).strip() == contact_uri:
                return key
            if aor_value and str(metadata.get("aor", "")).strip() == aor_value:
                return key
            if phone_number and str(metadata.get("phone_number", "")).strip() == phone_number:
                return key
            if imsi and str(metadata.get("imsi", "")).strip() == imsi:
                return key

        return preferred_key

    def _upsert_discovered_device(
        self,
        phone_number: str,
        imsi: str,
        ip_address: str,
        contact_uri: str,
        aor_value: str,
        user_agent: str,
        src: Endpoint,
        register_hint: bool,
        subscribe_hint: bool,
    ) -> None:
        existing_key = self._find_existing_discovered_key(
            phone_number=phone_number,
            imsi=imsi,
            ip_address=ip_address,
            contact_uri=contact_uri,
            aor_value=aor_value,
        )
        existing = self.discovered_register_devices.get(existing_key)
        now_unix = int(time.time())
        now_iso = self._now_utc_iso()

        existing_metadata: Dict[str, Any] = {}
        if existing and isinstance(existing.get("metadata"), dict):
            existing_metadata = dict(existing.get("metadata") or {})

        resolved_ip = ip_address or str(existing.get("address", "")).strip() if existing else ip_address
        if not resolved_ip:
            return

        resolved_phone_number = phone_number or str(existing_metadata.get("phone_number", "")).strip()
        resolved_imsi = imsi or str(existing_metadata.get("imsi", "")).strip()
        resolved_contact_uri = contact_uri or str(existing_metadata.get("contact_uri", "")).strip()
        resolved_aor_value = aor_value or str(existing_metadata.get("aor", "")).strip()
        resolved_user_agent = user_agent or str(existing_metadata.get("user_agent", "")).strip()

        register_count = int(existing_metadata.get("register_count", 0) or 0)
        subscribe_hint_count = int(existing_metadata.get("subscribe_hint_count", 0) or 0)
        if register_hint:
            register_count += 1
        if subscribe_hint:
            subscribe_hint_count += 1

        discovered_from = str(existing_metadata.get("discovered_from", "")).strip() or "sip-register"
        if register_hint and subscribe_hint_count > 0:
            discovered_from = "sip-register+subscribe-hint"
        elif subscribe_hint and register_count > 0:
            discovered_from = "sip-register+subscribe-hint"
        elif subscribe_hint:
            discovered_from = "sip-subscribe-hint"
        elif register_hint:
            discovered_from = "sip-register"

        record_id = str(existing.get("id", "")).strip() if existing else ""
        if not record_id:
            primary_identity = resolved_phone_number or resolved_imsi
            record_id = self._build_discovered_device_id(primary_identity, resolved_ip)

        record_name = str(existing.get("name", "")).strip() if existing else ""
        if not record_name:
            primary_identity = resolved_phone_number or resolved_imsi
            record_name = self._build_discovered_device_name(primary_identity, resolved_ip)

        first_seen_unix = int(existing_metadata.get("first_seen_unix", now_unix) or now_unix)
        first_seen_utc = str(existing_metadata.get("first_seen_utc", now_iso) or now_iso)

        metadata: Dict[str, Any] = {
            "discovered_from": discovered_from,
            "phone_number": resolved_phone_number,
            "imsi": resolved_imsi,
            "contact_uri": resolved_contact_uri,
            "aor": resolved_aor_value,
            "user_agent": resolved_user_agent,
            "register_count": register_count,
            "subscribe_hint_count": subscribe_hint_count,
            "first_seen_unix": first_seen_unix,
            "first_seen_utc": first_seen_utc,
            "last_seen_unix": now_unix,
            "last_seen_utc": now_iso,
            "source_host": src.host,
            "source_port": src.port,
            "source_transport": src.transport,
        }

        final_key = self._build_discovered_device_key(
            resolved_phone_number,
            resolved_ip,
            resolved_contact_uri,
            resolved_aor_value,
        )
        if not final_key:
            return

        if existing_key and existing_key != final_key:
            self.discovered_register_devices.pop(existing_key, None)

        self.discovered_register_devices[final_key] = {
            "id": record_id,
            "name": record_name,
            "address": resolved_ip,
            "metadata": metadata,
        }

        max_entries = max(self.discovered_register_max_entries, 0)
        if max_entries and len(self.discovered_register_devices) > max_entries:
            ranked = sorted(
                self.discovered_register_devices.items(),
                key=lambda item: int(
                    (
                        dict(item[1].get("metadata", {})).get("last_seen_unix", 0)
                        if isinstance(item[1].get("metadata", {}), dict)
                        else 0
                    )
                    or 0
                ),
            )
            trim_count = len(self.discovered_register_devices) - max_entries
            for stale_key, _ in ranked[:trim_count]:
                self.discovered_register_devices.pop(stale_key, None)

    def _tester_event(self, correlation_id: str) -> asyncio.Event:
        event = self.tester_response_events.get(correlation_id)
        if event is None:
            event = asyncio.Event()
            self.tester_response_events[correlation_id] = event
        return event

    def _record_tester_response(self, correlation_id: str, raw_response: str) -> None:
        queue = self.tester_responses.setdefault(correlation_id, [])
        queue.append(raw_response)
        if len(queue) > self.tester_max_buffered_responses:
            del queue[: len(queue) - self.tester_max_buffered_responses]
        self._tester_event(correlation_id).set()

    def _drain_tester_responses(self, correlation_id: str) -> List[str]:
        queue = self.tester_responses.get(correlation_id, [])
        if not queue:
            return []
        drained = list(queue)
        self.tester_responses[correlation_id] = []
        return drained

    def _message_method(self, msg: SIPMessage) -> str:
        if msg.is_response:
            cseq = msg.get_header("CSeq") or ""
            _, cseq_method = self._parse_cseq(cseq)
            return cseq_method or "RESPONSE"
        return msg.method or ""

    def _select_tester_submission_target(self, requested_target: Endpoint) -> Endpoint:
        # IMS handsets expect signaling via P-CSCF; direct SIP injection to UE is ignored.
        if self.tester_route_via_pcscf and self.pcscf_ip:
            return Endpoint(self.pcscf_ip, self.pcscf_port, "udp")
        return requested_target

    def _record_live_edit_hit(
        self,
        rule: Dict[str, Any],
        msg: SIPMessage,
        src: Optional[Endpoint] = None,
        dst: Optional[Endpoint] = None,
    ) -> None:
        self.live_edit_hit_sequence += 1
        rule_direction = self._sanitize_rule_direction(rule.get("direction", "any"))
        hit = {
            "sequence": self.live_edit_hit_sequence,
            "timestamp": int(time.time()),
            "rule_id": str(rule.get("id", "")),
            "direction": rule_direction,
            "sip_direction": "response" if msg.is_response else "request",
            "method": self._message_method(msg),
            "start_line": msg.start_line,
            "src_host": src.host if src is not None else "",
            "dst_host": dst.host if dst is not None else "",
        }
        self.live_edit_hits.append(hit)
        if len(self.live_edit_hits) > self.live_edit_max_buffered_hits:
            del self.live_edit_hits[: len(self.live_edit_hits) - self.live_edit_max_buffered_hits]
        self.live_edit_hit_event.set()

    def _find_live_edit_hit(
        self,
        rule_id_filter: Optional[Set[str]],
        since_sequence: int,
        method_filter: str,
        direction_filter: str,
        ignored_direction_sequences: Optional[Set[int]] = None,
        ignored_direction_hits: Optional[List[Dict[str, Any]]] = None,
    ) -> Optional[Dict[str, Any]]:
        normalized_method = self._sanitize_rule_method(method_filter)
        normalized_direction = self._sanitize_rule_direction(direction_filter)

        for hit in self.live_edit_hits:
            hit_sequence = int(hit.get("sequence", 0))
            if hit_sequence <= since_sequence:
                continue

            hit_rule_id = str(hit.get("rule_id", ""))
            if rule_id_filter is not None and hit_rule_id not in rule_id_filter:
                continue

            hit_method = str(hit.get("method", "")).upper()
            if normalized_method not in {"*", "ANY", ""} and hit_method != normalized_method:
                continue

            hit_direction = self._sanitize_rule_direction(
                str(hit.get("sip_direction", hit.get("direction", "any")))
            )
            if normalized_direction != "any" and hit_direction != normalized_direction:
                if ignored_direction_sequences is not None and hit_sequence not in ignored_direction_sequences:
                    ignored_direction_sequences.add(hit_sequence)
                    start_line = str(hit.get("start_line", "")).strip() or "<unknown>"
                    self._log(
                        f"Ignoring message {start_line}: only looking for {normalized_direction} messages"
                    )
                    if ignored_direction_hits is not None:
                        ignored_direction_hits.append(
                            {
                                "sequence": hit_sequence,
                                "start_line": start_line,
                                "actual_direction": hit_direction,
                                "required_direction": normalized_direction,
                            }
                        )
                continue

            return dict(hit)

        return None

    async def submit_tester_message(
        self,
        raw_message: str,
        target: Endpoint,
        correlation_id: Optional[str] = None,
    ) -> Dict[str, str]:
        message = SIPMessage.parse(raw_message.encode("latin1", errors="replace"))
        tester_correlation_id = (correlation_id or uuid.uuid4().hex).strip()
        effective_target = self._select_tester_submission_target(target)
        selected_device_host = self._normalize_host_for_match(target.host)
        message.set_header("X-SIP-Proxy-Target", self._format_target_uri(effective_target))
        message.set_header("X-IMS-Tester-Correlation-ID", tester_correlation_id)
        if selected_device_host:
            message.set_header("X-IMS-Tester-Device-Host", selected_device_host)

        # Synthetic source endpoint used only for transaction bookkeeping.
        tester_source = Endpoint(host="ims-tester", port=0, transport="tester")
        await self._handle_request(message, tester_source)
        self._tester_event(tester_correlation_id)

        return {
            "correlation_id": tester_correlation_id,
            "target": f"{effective_target.host}:{effective_target.port}/{effective_target.transport}",
        }

    async def read_tester_responses(self, correlation_id: str, timeout_seconds: float) -> List[str]:
        tester_correlation_id = correlation_id.strip()
        if not tester_correlation_id:
            return []

        drained = self._drain_tester_responses(tester_correlation_id)
        if drained:
            return drained

        wait_timeout = timeout_seconds if timeout_seconds > 0 else 0.0
        event = self._tester_event(tester_correlation_id)
        event.clear()
        if wait_timeout == 0.0:
            return []

        try:
            await asyncio.wait_for(event.wait(), timeout=wait_timeout)
        except asyncio.TimeoutError:
            return []

        event.clear()
        return self._drain_tester_responses(tester_correlation_id)

    async def get_discovered_devices(self) -> List[Dict[str, Any]]:
        devices: List[Dict[str, Any]] = []
        for raw in self.discovered_register_devices.values():
            metadata = raw.get("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}

            devices.append(
                {
                    "id": str(raw.get("id", "")),
                    "name": str(raw.get("name", "")),
                    "address": str(raw.get("address", "")),
                    "metadata": dict(metadata),
                }
            )

        devices.sort(
            key=lambda item: int(dict(item.get("metadata", {})).get("last_seen_unix", 0) or 0),
            reverse=True,
        )
        return devices

    async def get_live_edit_rules(self) -> List[Dict[str, Any]]:
        return [dict(rule) for rule in self.rewrite_rules]

    async def replace_live_edit_rules(self, rules: List[Any]) -> List[Dict[str, Any]]:
        self.rewrite_rules = self._normalize_rewrite_rules(rules)
        return [dict(rule) for rule in self.rewrite_rules]

    async def add_live_edit_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        normalized = self._normalize_rewrite_rule(rule)
        if normalized is None:
            raise ValueError("invalid live edit rule")
        self.rewrite_rules.append(normalized)
        return dict(normalized)

    async def clear_live_edit_rules(self) -> int:
        count = len(self.rewrite_rules)
        self.rewrite_rules = []
        return count

    async def configure_invite_content_type_rewrite(self, content_type: str, clear_existing: bool) -> Dict[str, Any]:
        if clear_existing:
            self.rewrite_rules = []

        normalized = self._normalize_rewrite_rule(
            {
                "enabled": True,
                "direction": "request",
                "method": "INVITE",
                "action": "set-header",
                "header": "Content-Type",
                "value": content_type,
            }
        )
        if normalized is None:
            raise ValueError("failed to build INVITE Content-Type rewrite rule")

        self.rewrite_rules.append(normalized)
        return dict(normalized)

    async def wait_for_live_edit_hit(
        self,
        rule_ids: List[str],
        timeout_seconds: float,
        since_sequence: Optional[int] = None,
        method: str = "*",
        direction: str = "any",
    ) -> Dict[str, Any]:
        rule_id_filter: Optional[Set[str]] = None
        cleaned_rule_ids = [rule_id.strip() for rule_id in rule_ids if rule_id.strip()]
        if cleaned_rule_ids:
            rule_id_filter = set(cleaned_rule_ids)

        if since_sequence is None:
            since = self.live_edit_hit_sequence
        else:
            try:
                since = max(int(since_sequence), 0)
            except (TypeError, ValueError):
                since = self.live_edit_hit_sequence

        ignored_direction_sequences: Set[int] = set()
        ignored_direction_hits: List[Dict[str, Any]] = []

        hit = self._find_live_edit_hit(
            rule_id_filter=rule_id_filter,
            since_sequence=since,
            method_filter=method,
            direction_filter=direction,
            ignored_direction_sequences=ignored_direction_sequences,
            ignored_direction_hits=ignored_direction_hits,
        )
        if hit is not None:
            return {
                "matched": True,
                "since_sequence": since,
                "sequence": self.live_edit_hit_sequence,
                "hit": hit,
                "ignored_hits": list(ignored_direction_hits),
            }

        wait_timeout = timeout_seconds if timeout_seconds > 0 else 0.0
        if wait_timeout == 0.0:
            return {
                "matched": False,
                "since_sequence": since,
                "sequence": self.live_edit_hit_sequence,
                "hit": None,
                "ignored_hits": list(ignored_direction_hits),
            }

        loop = asyncio.get_running_loop()
        deadline = loop.time() + wait_timeout

        while True:
            hit = self._find_live_edit_hit(
                rule_id_filter=rule_id_filter,
                since_sequence=since,
                method_filter=method,
                direction_filter=direction,
                ignored_direction_sequences=ignored_direction_sequences,
                ignored_direction_hits=ignored_direction_hits,
            )
            if hit is not None:
                return {
                    "matched": True,
                    "since_sequence": since,
                    "sequence": self.live_edit_hit_sequence,
                    "hit": hit,
                    "ignored_hits": list(ignored_direction_hits),
                }

            remaining = deadline - loop.time()
            if remaining <= 0:
                return {
                    "matched": False,
                    "since_sequence": since,
                    "sequence": self.live_edit_hit_sequence,
                    "hit": None,
                    "ignored_hits": list(ignored_direction_hits),
                }

            self.live_edit_hit_event.clear()

            # A hit may arrive between computing remaining and clearing the event.
            hit = self._find_live_edit_hit(
                rule_id_filter=rule_id_filter,
                since_sequence=since,
                method_filter=method,
                direction_filter=direction,
                ignored_direction_sequences=ignored_direction_sequences,
                ignored_direction_hits=ignored_direction_hits,
            )
            if hit is not None:
                return {
                    "matched": True,
                    "since_sequence": since,
                    "sequence": self.live_edit_hit_sequence,
                    "hit": hit,
                    "ignored_hits": list(ignored_direction_hits),
                }

            try:
                await asyncio.wait_for(self.live_edit_hit_event.wait(), timeout=remaining)
            except asyncio.TimeoutError:
                return {
                    "matched": False,
                    "since_sequence": since,
                    "sequence": self.live_edit_hit_sequence,
                    "hit": None,
                    "ignored_hits": list(ignored_direction_hits),
                }

            hit = self._find_live_edit_hit(
                rule_id_filter=rule_id_filter,
                since_sequence=since,
                method_filter=method,
                direction_filter=direction,
                ignored_direction_sequences=ignored_direction_sequences,
                ignored_direction_hits=ignored_direction_hits,
            )
            if hit is not None:
                return {
                    "matched": True,
                    "since_sequence": since,
                    "sequence": self.live_edit_hit_sequence,
                    "hit": hit,
                    "ignored_hits": list(ignored_direction_hits),
                }

    async def handle_packet(self, data: bytes, src: Endpoint) -> None:
        try:
            msg = SIPMessage.parse(data)
        except Exception as exc:
            self._log(f"Dropping malformed SIP packet from {src.host}:{src.port}: {exc}")
            return

        if self.log_messages:
            self._log(f"RX {src.host}:{src.port} {msg.start_line}")

        rewrite_target = self._predict_response_target(msg, src) if msg.is_response else None
        self._apply_rewrites(msg, src=src, dst=rewrite_target)

        if msg.is_response:
            await self._handle_response(msg, src)
            return

        await self._handle_request(msg, src)

    async def handle_datagram(self, data: bytes, addr: Tuple[str, int]) -> None:
        src = Endpoint(host=addr[0], port=addr[1], transport="udp")
        await self.handle_packet(data, src)

    async def handle_tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        if not peer:
            writer.close()
            await writer.wait_closed()
            return

        src = Endpoint(host=peer[0], port=peer[1], transport="tcp")
        pending = b""

        try:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break

                pending += chunk
                messages, pending = split_sip_stream_messages(pending)
                for payload in messages:
                    try:
                        await self.handle_packet(payload, src)
                    except Exception as exc:
                        self._log(f"Unhandled error while processing TCP SIP message: {exc}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def _handle_request(self, msg: SIPMessage, src: Endpoint) -> None:
        from_pcscf = self._is_from_pcscf(src.host)
        tester_correlation_id = msg.get_header("X-IMS-Tester-Correlation-ID")
        tester_device_host = self._normalize_host_for_match(msg.get_header("X-IMS-Tester-Device-Host") or "")
        if tester_correlation_id:
            msg.remove_header("X-IMS-Tester-Correlation-ID")
        if tester_device_host:
            msg.remove_header("X-IMS-Tester-Device-Host")

        if msg.method == "REGISTER" and not tester_correlation_id:
            self._record_register_discovery(msg, src)

        if msg.method == "SUBSCRIBE" and not tester_correlation_id:
            self._record_subscribe_identity_hint(msg, src)

        target = self._determine_target_from_header(msg)

        inbound_vias = self._via_values(msg)
        inbound_top_via = inbound_vias[0] if inbound_vias else ""
        inbound_branch = self._extract_branch(inbound_top_via) or ""
        call_id = msg.get_header("Call-ID") or ""
        cseq = msg.get_header("CSeq") or ""
        cseq_num, _ = self._parse_cseq(cseq)

        if not from_pcscf:
            self._pop_proxy_route_if_needed(msg)

        if target is None:
            if from_pcscf:
                target = Endpoint(self.default_core_ip, self.default_core_port, "udp")
            else:
                target = Endpoint(self.pcscf_ip, self.pcscf_port, "udp")

        if not target.host:
            self._log("No valid target host for SIP request; dropping")
            return

        # Keep core leg stable over UDP for P-CSCF-originated requests.
        # One-shot TCP connect/close can make upstream proxies reply to closed
        # ephemeral ports, causing REGISTER timeout (504) downstream.
        if from_pcscf and target.transport.lower() == "tcp":
            target = Endpoint(target.host, target.port, "udp")

        cancel_route: Optional[CancelRoute] = None
        if msg.method == "CANCEL" and inbound_branch and call_id and cseq_num:
            key = self._cancel_route_key(src.host, inbound_branch, call_id, cseq_num)
            cancel_route = self.cancel_routes.get(key)
            if cancel_route is not None:
                target = cancel_route.target

        via_branch = cancel_route.outbound_branch if cancel_route else f"z9hG4bK-proxy-{uuid.uuid4().hex[:16]}"
        via_transport = "TCP" if target.transport.lower() == "tcp" else "UDP"
        via_value = f"SIP/2.0/{via_transport} {self.advertised_host}:{self.listen_port};branch={via_branch};rport"
        # Via must be prepended, not appended, so the response pops our Via first.
        msg.insert_header("Via", via_value)

        if self.insert_record_route and msg.method in {"INVITE", "SUBSCRIBE", "MESSAGE", "REFER", "UPDATE"}:
            to_h = (msg.get_header("To") or "").lower()
            if "tag=" not in to_h:
                rr = f"<sip:{self.route_user}@{self.advertised_host}:{self.listen_port};lr>"
                msg.insert_header("Record-Route", rr, after_names=["Via", "v"])

        top_via = msg.get_header("Via") or msg.get_header("v") or ""
        branch = self._extract_branch(top_via) or via_branch
        # For TCP-originated requests from P-CSCF, return responses to the
        # P-CSCF listener, not to the ephemeral client TCP source port.
        response_target = src
        if from_pcscf and src.transport == "tcp" and self.pcscf_ip:
            response_target = Endpoint(self.pcscf_ip, self.pcscf_port, "tcp")

        transaction_key = self._transaction_key(branch, cseq)
        self.transactions[transaction_key] = response_target
        if inbound_vias:
            self.transaction_upstream_vias[transaction_key] = inbound_vias
        if tester_correlation_id:
            self.tester_transaction_correlation[transaction_key] = tester_correlation_id
            if tester_device_host:
                self.tester_transaction_device_host[transaction_key] = tester_device_host

        if msg.method == "INVITE" and inbound_branch and call_id and cseq_num:
            key = self._cancel_route_key(src.host, inbound_branch, call_id, cseq_num)
            self.cancel_routes[key] = CancelRoute(target=target, outbound_branch=branch)

        out = msg.to_bytes()
        await self._send(out, target)

        if self.log_messages:
            self._log(f"TX {target.host}:{target.port}/{target.transport} {msg.start_line}")

    async def _handle_response(self, msg: SIPMessage, src: Endpoint) -> None:
        vias = msg.get_headers("Via")
        if not vias:
            self._log("Response without Via header dropped")
            return

        top_via_idx, top_via_val = vias[0]
        if not self._is_our_via(top_via_val):
            self._log("Response top Via does not belong to proxy; dropping to avoid corrupt forwarding")
            return

        branch = self._extract_branch(top_via_val) or ""
        cseq = msg.get_header("CSeq") or ""
        key = self._transaction_key(branch, cseq)
        tester_correlation_id = self.tester_transaction_correlation.get(key)
        tester_device_host = self.tester_transaction_device_host.get(key, "")

        target = self.transactions.get(key)
        if target is None:
            if self._is_from_pcscf(src.host):
                target = Endpoint(self.default_core_ip, self.default_core_port, "udp")
            else:
                target = Endpoint(self.pcscf_ip, self.pcscf_port, "udp")

        msg.headers.pop(top_via_idx)

        # Downstream entities may collapse or mutate pre-existing Via chains.
        # Re-apply the exact upstream chain captured on request ingress so that
        # each upstream hop can pop its own Via safely.
        expected_upstream_vias = self.transaction_upstream_vias.get(key, [])
        if expected_upstream_vias:
            current_vias = self._via_values(msg)
            if current_vias != expected_upstream_vias:
                self._replace_vias(msg, expected_upstream_vias)
        elif not self._via_values(msg):
            self._log("Response lost all Via headers and no upstream Via context exists; dropping")
            return

        out = msg.to_bytes()

        if tester_correlation_id:
            if tester_device_host and not self._response_matches_selected_device(msg, src, tester_device_host):
                if self.log_messages:
                    self._log(
                        f"Ignoring tester response that does not match selected device host {tester_device_host}: {msg.start_line}"
                    )
                if self._extract_status_code(msg.start_line) >= 200:
                    self.transactions.pop(key, None)
                    self.transaction_upstream_vias.pop(key, None)
                    self.tester_transaction_correlation.pop(key, None)
                    self.tester_transaction_device_host.pop(key, None)
                return

            self._record_tester_response(tester_correlation_id, out.decode("latin1", errors="replace"))

            # Keep provisional response correlation for later final responses.
            if self._extract_status_code(msg.start_line) >= 200:
                self.transactions.pop(key, None)
                self.transaction_upstream_vias.pop(key, None)
                self.tester_transaction_correlation.pop(key, None)
                self.tester_transaction_device_host.pop(key, None)

            if self.log_messages:
                self._log(f"TX tester[{tester_correlation_id}] {msg.start_line}")
            return

        await self._send(out, target)

        if self.log_messages:
            self._log(f"TX {target.host}:{target.port}/{target.transport} {msg.start_line}")

class SIPUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, proxy: SIPProxy):
        self.proxy = proxy

    def connection_made(self, transport) -> None:
        self.proxy.udp_transport = transport
        self.proxy._log(f"SIP UDP listening on {self.proxy.listen_ip}:{self.proxy.listen_port}")

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        asyncio.create_task(self.proxy.handle_datagram(data, addr))


class ProxyAPIHandler(BaseHTTPRequestHandler):
    server_version = "SIPProxyTesterAPI/1.0"

    @staticmethod
    def _as_bool(value: Any, default: bool = False) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _json_response(self, code: int, payload: Dict[str, Any]) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self) -> Optional[Dict[str, Any]]:
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0:
            return {}

        raw = self.rfile.read(content_length)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self._json_response(400, {"error": "invalid json"})
            return None

        if not isinstance(parsed, dict):
            self._json_response(400, {"error": "json body must be an object"})
            return None

        return parsed

    def _parse_target(self, payload: Dict[str, Any]) -> Optional[Endpoint]:
        if isinstance(payload.get("target_uri"), str):
            target_uri = str(payload.get("target_uri", "")).strip()
            if target_uri:
                host, port, transport, _ = parse_sip_uri(target_uri)
                if host:
                    return Endpoint(host=host, port=port, transport=transport)

        target = payload.get("target", {})
        if not isinstance(target, dict):
            self._json_response(400, {"error": "target must be an object"})
            return None

        host = str(target.get("host", "")).strip()
        if not host:
            self._json_response(400, {"error": "target.host is required"})
            return None

        try:
            port = int(target.get("port", 5060))
        except (TypeError, ValueError):
            self._json_response(400, {"error": "target.port must be an integer"})
            return None

        transport = str(target.get("transport", "udp")).strip().lower() or "udp"
        if transport not in {"udp", "tcp"}:
            self._json_response(400, {"error": "target.transport must be udp or tcp"})
            return None

        return Endpoint(host=host, port=port, transport=transport)

    def _run_proxy_coro(self, coro, timeout_seconds: float):
        proxy: SIPProxy = self.server.proxy  # type: ignore[attr-defined]
        if proxy.loop is None:
            raise RuntimeError("proxy loop is not initialized")
        future = asyncio.run_coroutine_threadsafe(coro, proxy.loop)
        return future.result(timeout=max(timeout_seconds, 0.2))

    def do_GET(self) -> None:
        if self.path == "/health":
            self._json_response(200, {"status": "ok"})
            return

        if self.path == "/tester/discovered-devices":
            self._handle_discovered_devices_get()
            return

        if self.path == "/tester/live-edit-rules":
            self._handle_live_edit_rules_get()
            return

        self._json_response(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path == "/tester/send":
            self._handle_tester_send()
            return

        if self.path == "/tester/read":
            self._handle_tester_read()
            return

        if self.path == "/tester/live-edit-rules":
            self._handle_live_edit_rules_post()
            return

        if self.path == "/tester/live-edit-rules/invite-content-type":
            self._handle_live_edit_invite_content_type()
            return

        if self.path == "/tester/live-edit-wait":
            self._handle_live_edit_wait()
            return

        self._json_response(404, {"error": "not found"})

    def do_DELETE(self) -> None:
        if self.path == "/tester/live-edit-rules":
            self._handle_live_edit_rules_delete()
            return

        self._json_response(404, {"error": "not found"})

    def _handle_tester_send(self) -> None:
        payload = self._read_json_body()
        if payload is None:
            return

        raw_message = str(payload.get("raw_message", ""))
        if not raw_message.strip():
            self._json_response(400, {"error": "raw_message is required"})
            return

        target = self._parse_target(payload)
        if target is None:
            return

        correlation_id_raw = payload.get("correlation_id")
        correlation_id: Optional[str]
        if correlation_id_raw is None:
            correlation_id = None
        else:
            correlation_id = str(correlation_id_raw).strip() or None

        timeout_seconds = 5.0
        try:
            timeout_seconds = float(payload.get("submit_timeout_seconds", 5.0))
        except (TypeError, ValueError):
            pass

        proxy: SIPProxy = self.server.proxy  # type: ignore[attr-defined]
        try:
            result = self._run_proxy_coro(
                proxy.submit_tester_message(
                    raw_message=raw_message,
                    target=target,
                    correlation_id=correlation_id,
                ),
                timeout_seconds=timeout_seconds,
            )
        except Exception as exc:
            self._json_response(500, {"error": str(exc)})
            return

        self._json_response(202, {"status": "accepted", **result})

    def _handle_discovered_devices_get(self) -> None:
        proxy: SIPProxy = self.server.proxy  # type: ignore[attr-defined]
        try:
            devices = self._run_proxy_coro(proxy.get_discovered_devices(), timeout_seconds=2.0)
        except Exception as exc:
            self._json_response(500, {"error": str(exc)})
            return

        self._json_response(200, {"count": len(devices), "devices": devices})

    def _handle_tester_read(self) -> None:
        payload = self._read_json_body()
        if payload is None:
            return

        correlation_id = str(payload.get("correlation_id", "")).strip()
        if not correlation_id:
            self._json_response(400, {"error": "correlation_id is required"})
            return

        timeout_seconds = 3.0
        try:
            timeout_seconds = float(payload.get("timeout_seconds", 3.0))
        except (TypeError, ValueError):
            pass

        proxy: SIPProxy = self.server.proxy  # type: ignore[attr-defined]
        try:
            responses = self._run_proxy_coro(
                proxy.read_tester_responses(correlation_id=correlation_id, timeout_seconds=timeout_seconds),
                timeout_seconds=timeout_seconds + 1.0,
            )
        except Exception as exc:
            self._json_response(500, {"error": str(exc)})
            return

        self._json_response(
            200,
            {
                "correlation_id": correlation_id,
                "count": len(responses),
                "responses": responses,
            },
        )

    def _handle_live_edit_rules_get(self) -> None:
        proxy: SIPProxy = self.server.proxy  # type: ignore[attr-defined]
        try:
            rules = self._run_proxy_coro(proxy.get_live_edit_rules(), timeout_seconds=2.0)
        except Exception as exc:
            self._json_response(500, {"error": str(exc)})
            return

        self._json_response(200, {"count": len(rules), "rules": rules})

    def _handle_live_edit_rules_post(self) -> None:
        payload = self._read_json_body()
        if payload is None:
            return

        proxy: SIPProxy = self.server.proxy  # type: ignore[attr-defined]

        if "rules" in payload:
            rules_value = payload.get("rules")
            if not isinstance(rules_value, list):
                self._json_response(400, {"error": "rules must be a list"})
                return
            try:
                rules = self._run_proxy_coro(
                    proxy.replace_live_edit_rules(rules_value),
                    timeout_seconds=3.0,
                )
            except Exception as exc:
                self._json_response(500, {"error": str(exc)})
                return
            self._json_response(200, {"status": "ok", "count": len(rules), "rules": rules})
            return

        if "rule" in payload:
            rule_value = payload.get("rule")
            if not isinstance(rule_value, dict):
                self._json_response(400, {"error": "rule must be an object"})
                return
            try:
                rule = self._run_proxy_coro(
                    proxy.add_live_edit_rule(rule_value),
                    timeout_seconds=3.0,
                )
            except Exception as exc:
                self._json_response(500, {"error": str(exc)})
                return
            self._json_response(200, {"status": "ok", "rule": rule})
            return

        self._json_response(400, {"error": "expected 'rules' list or 'rule' object"})

    def _handle_live_edit_rules_delete(self) -> None:
        proxy: SIPProxy = self.server.proxy  # type: ignore[attr-defined]
        try:
            cleared = self._run_proxy_coro(proxy.clear_live_edit_rules(), timeout_seconds=2.0)
        except Exception as exc:
            self._json_response(500, {"error": str(exc)})
            return

        self._json_response(200, {"status": "ok", "cleared": cleared})

    def _handle_live_edit_invite_content_type(self) -> None:
        payload = self._read_json_body()
        if payload is None:
            return

        content_type = str(payload.get("content_type", "test")).strip() or "test"
        clear_existing = self._as_bool(payload.get("clear_existing"), default=True)

        proxy: SIPProxy = self.server.proxy  # type: ignore[attr-defined]
        try:
            rule = self._run_proxy_coro(
                proxy.configure_invite_content_type_rewrite(content_type, clear_existing),
                timeout_seconds=3.0,
            )
            rules = self._run_proxy_coro(proxy.get_live_edit_rules(), timeout_seconds=2.0)
        except Exception as exc:
            self._json_response(500, {"error": str(exc)})
            return

        self._json_response(
            200,
            {
                "status": "ok",
                "rule": rule,
                "count": len(rules),
                "rules": rules,
            },
        )

    def _handle_live_edit_wait(self) -> None:
        payload = self._read_json_body()
        if payload is None:
            return

        rule_ids_raw = payload.get("rule_ids", [])
        if not isinstance(rule_ids_raw, list):
            self._json_response(400, {"error": "rule_ids must be a list"})
            return
        rule_ids = [str(item).strip() for item in rule_ids_raw if str(item).strip()]

        since_sequence_raw = payload.get("since_sequence")
        since_sequence: Optional[int] = None
        if since_sequence_raw is not None:
            try:
                since_sequence = int(since_sequence_raw)
            except (TypeError, ValueError):
                self._json_response(400, {"error": "since_sequence must be an integer"})
                return

        timeout_seconds = 30.0
        try:
            timeout_seconds = float(payload.get("timeout_seconds", 30.0))
        except (TypeError, ValueError):
            pass

        method = str(payload.get("method", "*")).strip() or "*"
        direction = str(payload.get("direction", "any")).strip() or "any"

        proxy: SIPProxy = self.server.proxy  # type: ignore[attr-defined]
        try:
            result = self._run_proxy_coro(
                proxy.wait_for_live_edit_hit(
                    rule_ids=rule_ids,
                    timeout_seconds=timeout_seconds,
                    since_sequence=since_sequence,
                    method=method,
                    direction=direction,
                ),
                timeout_seconds=timeout_seconds + 1.0,
            )
        except Exception as exc:
            self._json_response(500, {"error": str(exc)})
            return

        self._json_response(200, result)


def start_api_server(proxy: SIPProxy) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((proxy.api_listen_ip, proxy.api_port), ProxyAPIHandler)
    server.proxy = proxy  # type: ignore[attr-defined]

    def _serve_forever() -> None:
        proxy._log(f"SIP tester API listening on {proxy.api_listen_ip}:{proxy.api_port}")
        server.serve_forever()

    thread = threading.Thread(target=_serve_forever, daemon=True)
    thread.start()
    return server


async def run() -> None:
    proxy = SIPProxy()
    loop = asyncio.get_running_loop()
    proxy.loop = loop

    if not proxy.pcscf_ip:
        proxy._log("SIP_PROXY_PCSCF_IP is empty; proxy cannot route traffic to P-CSCF")

    transport, _ = await loop.create_datagram_endpoint(
        lambda: SIPUDPProtocol(proxy),
        local_addr=(proxy.listen_ip, proxy.listen_port),
    )
    proxy._log(f"SIP TCP listening on {proxy.listen_ip}:{proxy.listen_port}")
    proxy.tcp_server = await asyncio.start_server(
        proxy.handle_tcp_client,
        host=proxy.listen_ip,
        port=proxy.listen_port,
    )

    api_server: Optional[ThreadingHTTPServer] = None
    if proxy.api_enabled:
        api_server = start_api_server(proxy)

    try:
        await asyncio.Future()
    finally:
        if api_server is not None:
            api_server.shutdown()
            api_server.server_close()
        if proxy.tcp_server is not None:
            proxy.tcp_server.close()
            await proxy.tcp_server.wait_closed()
        transport.close()


if __name__ == "__main__":
    asyncio.run(run())
