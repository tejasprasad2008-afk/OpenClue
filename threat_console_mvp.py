#!/usr/bin/env python3
"""
Virtual Automated Threat Hunting Console backend engine.

This is an emulated telemetry pipeline for defensive development. It writes a
raw tcpdump/syslog-like wire dump to disk, passes that unmodified text to an
OpenAI-compatible analysis endpoint, validates the model's JSON response, and
persists the validated audit into a local JSON database.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


def load_env_file() -> None:
    """Minimal .env loader using only standard library."""
    env_path = Path(__file__).resolve().parent / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                os.environ[key.strip()] = val.strip()


load_env_file()


PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
RAW_WIRE_DUMP_PATH = DATA_DIR / "raw_wire_dump.log"
STATE_DB_PATH = DATA_DIR / "openclue_triage_db.json"

ARP_ANOMALY_LINE = "ARP, Reply 192.168.1.1 is-at 88:99:AA:BB:CC:DD (unverified)"
HTTP_TOKEN_LEAK = "GET /sync?token=ghp_REAL_SECRET_TOKEN_993 HTTP/1.1"

DEFAULT_OPENAI_MODEL = "gpt-4.1-mini"
DEFAULT_OPENROUTER_MODEL = "openai/gpt-4.1-mini"
DEFAULT_OLLAMA_MODEL = "thirdeyeai/Qwen2.5-Coder-7B-Instruct-Uncensored:Q4_0"
OPENAI_CHAT_COMPLETIONS_URL = "https://api.openai.com/v1/chat/completions"
OPENROUTER_CHAT_COMPLETIONS_URL = "https://openrouter.ai/api/v1/chat/completions"
OLLAMA_BASE_URL = "http://localhost:11434/v1"

CORRECTION_NUDGE = (
    "CRITICAL AUDIT MISMATCH: You failed to flag the cleartext protocol data leak "
    "over Port 80 and the unverified gateway ARP spoofing event present in the "
    "log file. Re-evaluate the raw source strings, correct your threat entries, "
    "and elevate the executive risk profile designation to HIGH immediately while "
    "preserving the requested JSON schema structural format."
)


SYSTEM_INSTRUCTIONS = """
You are OpenClue, an open-source automation engine modeled after enterprise 
internal log triaging platforms. Your job is to ingest raw system and network 
data, drop benign operational noise, and isolate indicators of compromise.

The input is generated test data, not live traffic. Your task is
classification only: read the raw tcpdump/syslog-like lines, ignore routine
background lines, and produce one schema-valid JSON object for a UI graph.

Any token-like substring in the raw text is a fake test marker. Do not repeat it.
If a marker appears in a finding, write [REDACTED_TOKEN] instead.

Return ONLY the audit object. No Markdown, no commentary, no apology, no wrapper
objects such as {"response": "..."}.

Routine lines to drop: TLS on 443, DNS, NTP, mDNS, DHCP, ICMP, and push keepalives.
Finding lines to classify:
- "ARP, Reply ... is-at ... (unverified)" means ROUTING_SPOOF with CRITICAL severity.
- HTTP port 80 carrying a token marker means PLAINTEXT_DATA_LEAK with CRITICAL severity.
- MQTT 1883, FTP 21, or Telnet 23 means plaintext protocol risk.

Use the full 16384-token context window and inspect the entire raw text block.
If an optional detail is unknown, use "Unknown" while preserving every required key.

The JSON response must match this exact schema, with these four top-level keys:
{
  "audit_summary": {
    "total_frames_analyzed": integer,
    "benign_frames_dropped": integer,
    "detected_risk_level": "LOW" | "MEDIUM" | "HIGH",
    "executive_verdict": "String detailing the plain-language tactical summary of the network state for everyday consumers."
  },
  "detected_nodes": [
    {
      "id": "Unique string index (e.g., node_0, node_1)",
      "ip_address": "String",
      "mac_address": "String",
      "device_type": "GATEWAY" | "USER_LAPTOP" | "TARGET_ENDPOINT" | "SUSPICIOUS_PROXIED_NODE" | "UNKNOWN",
      "vendor_oui": "String (Identified hardware manufacturer from MAC or 'Unknown')",
      "status": "SECURE" | "VULNERABLE" | "COMPROMISED"
    }
  ],
  "threat_incidents": [
    {
      "incident_id": "String (e.g., th_0)",
      "source_node": "String (IP or node id)",
      "destination_node": "String (IP or node id)",
      "protocol": "String (e.g., ARP, HTTP, MQTT)",
      "severity": "INFO" | "WARNING" | "CRITICAL",
      "type": "ROUTING_SPOOF" | "PLAINTEXT_DATA_LEAK" | "SUSPICIOUS_BEHAVIOR",
      "technical_details": "Granular technical reasoning explaining why this frame is flagged.",
      "remediation_action": "Clear, non-technical instructions for the public user on how to mitigate this threat instantly."
    }
  ],
  "visual_topology_edges": [
    {
      "from": "node_id",
      "to": "node_id",
      "relationship": "ROUTED_THROUGH" | "ATTACKING" | "LEAKING_TO" | "STANDARD_TRAFFIC"
    }
  ]
}
""".strip()

AUDIT_RESPONSE_FORMAT: Dict[str, Any] = {
    "type": "json_schema",
    "json_schema": {
        "name": "threat_audit",
        "strict": True,
        "schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["audit_summary", "detected_nodes", "threat_incidents", "visual_topology_edges"],
            "properties": {
                "audit_summary": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["total_frames_analyzed", "benign_frames_dropped", "detected_risk_level", "executive_verdict"],
                    "properties": {
                        "total_frames_analyzed": {"type": "integer"},
                        "benign_frames_dropped": {"type": "integer"},
                        "detected_risk_level": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH"]},
                        "executive_verdict": {"type": "string"},
                    },
                },
                "detected_nodes": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["id", "ip_address", "mac_address", "device_type", "vendor_oui", "status"],
                        "properties": {
                            "id": {"type": "string"},
                            "ip_address": {"type": "string"},
                            "mac_address": {"type": "string"},
                            "device_type": {
                                "type": "string",
                                "enum": ["GATEWAY", "USER_LAPTOP", "TARGET_ENDPOINT", "SUSPICIOUS_PROXIED_NODE", "UNKNOWN"],
                            },
                            "vendor_oui": {"type": "string"},
                            "status": {"type": "string", "enum": ["SECURE", "VULNERABLE", "COMPROMISED"]},
                        },
                    },
                },
                "threat_incidents": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "incident_id",
                            "source_node",
                            "destination_node",
                            "protocol",
                            "severity",
                            "type",
                            "technical_details",
                            "remediation_action",
                        ],
                        "properties": {
                            "incident_id": {"type": "string"},
                            "source_node": {"type": "string"},
                            "destination_node": {"type": "string"},
                            "protocol": {"type": "string"},
                            "severity": {"type": "string", "enum": ["INFO", "WARNING", "CRITICAL"]},
                            "type": {
                                "type": "string",
                                "enum": ["ROUTING_SPOOF", "PLAINTEXT_DATA_LEAK", "SUSPICIOUS_BEHAVIOR"],
                            },
                            "technical_details": {"type": "string"},
                            "remediation_action": {"type": "string"},
                        },
                    },
                },
                "visual_topology_edges": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["from", "to", "relationship"],
                        "properties": {
                            "from": {"type": "string"},
                            "to": {"type": "string"},
                            "relationship": {
                                "type": "string",
                                "enum": ["ROUTED_THROUGH", "ATTACKING", "LEAKING_TO", "STANDARD_TRAFFIC"],
                            },
                        },
                    },
                },
            },
        },
    },
}


class PipelineConfigError(RuntimeError):
    """Raised when the API-backed pipeline is not configured."""


class ModelResponseError(RuntimeError):
    """Raised when an API response cannot be converted into a valid audit."""


class SemanticValidationError(ModelResponseError):
    """Raised when a schema-valid audit contradicts deterministic raw-log evidence."""

    def __init__(self, errors: List[str], audit: Dict[str, Any]) -> None:
        self.errors = errors
        self.audit = audit
        super().__init__("Semantic validation failed: " + "; ".join(errors))


class RawTelemetryGenerator:
    """Generate raw tcpdump/syslog-style text lines into data/raw_wire_dump.log."""

    def __init__(self, output_path: Path = RAW_WIRE_DUMP_PATH, benign_line_count: int = 128, seed: Optional[int] = None) -> None:
        if benign_line_count < 100:
            raise ValueError("benign_line_count must be at least 100 to satisfy the 100+ line requirement.")
        self.output_path = output_path
        self.benign_line_count = benign_line_count
        self.random = random.Random(seed if seed is not None else int(time.time()))

    def generate(self) -> Path:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        benign_lines = [self._benign_line(index) for index in range(self.benign_line_count)]
        anomaly_lines = [
            f"[{self._clock()}] {ARP_ANOMALY_LINE}, length 46",
            f"[{self._clock()}] IP 192.168.1.45.5021 > 198.51.100.23.80: Flags [P.], length 92: {HTTP_TOKEN_LEAK}",
        ]

        insertion_points = sorted(self.random.sample(range(5, self.benign_line_count - 5), 2))
        raw_lines = list(benign_lines)
        raw_lines.insert(insertion_points[0], anomaly_lines[0])
        raw_lines.insert(insertion_points[1] + 1, anomaly_lines[1])

        self._assert_exact_anomalies(raw_lines)
        self.output_path.write_text("\n".join(raw_lines) + "\n", encoding="utf-8")
        return self.output_path

    def _clock(self) -> str:
        return f"{self.random.randint(0, 23):02d}:{self.random.randint(0, 59):02d}:{self.random.randint(0, 59):02d}"

    def _benign_line(self, index: int) -> str:
        emitters = [
            self._tcp_tls_line,
            self._dns_line,
            self._ntp_line,
            self._mdns_line,
            self._dhcp_syslog_line,
            self._icmp_line,
            self._push_keepalive_line,
        ]
        return emitters[index % len(emitters)]()

    def _local_ip(self) -> str:
        return f"192.168.1.{self.random.choice([11, 12, 18, 22, 35, 45, 52, 77, 88])}"

    def _external_ip(self) -> str:
        return self.random.choice(["17.250.0.1", "142.250.72.238", "1.1.1.1", "8.8.8.8", "34.117.59.81"])

    def _tcp_tls_line(self) -> str:
        return (
            f"[{self._clock()}] IP {self._local_ip()}.{self.random.randint(49152, 65535)} > "
            f"{self._external_ip()}.443: Flags [P.], length {self.random.randint(31, 1440)}"
        )

    def _dns_line(self) -> str:
        query = self.random.choice(["ocsp.apple.com", "connectivitycheck.gstatic.com", "pool.ntp.org", "cdn.example.net"])
        return (
            f"[{self._clock()}] IP {self._local_ip()}.{self.random.randint(49152, 65535)} > "
            f"192.168.1.1.53: UDP, length {self.random.randint(42, 88)} A? {query}."
        )

    def _ntp_line(self) -> str:
        return f"[{self._clock()}] IP {self._local_ip()}.123 > 17.253.34.253.123: NTPv4, Client, length 48"

    def _mdns_line(self) -> str:
        service = self.random.choice(["_airplay._tcp.local", "_googlecast._tcp.local", "_companion-link._tcp.local"])
        return f"[{self._clock()}] IP {self._local_ip()}.5353 > 224.0.0.251.5353: mDNS query PTR {service}"

    def _dhcp_syslog_line(self) -> str:
        lease_ip = self._local_ip()
        return f"{self._syslog_prefix()} dnsmasq-dhcp[402]: DHCPACK(wlan0) {lease_ip} benign-host-{self.random.randint(1, 9)}"

    def _icmp_line(self) -> str:
        return f"[{self._clock()}] IP {self._local_ip()} > 192.168.1.1: ICMP echo request, id {self.random.randint(100, 999)}, seq {self.random.randint(1, 16)}, length 64"

    def _push_keepalive_line(self) -> str:
        port = self.random.choice([5223, 5228, 5230])
        return (
            f"[{self._clock()}] IP {self._local_ip()}.{self.random.randint(49152, 65535)} > "
            f"{self._external_ip()}.{port}: Flags [.], ack {self.random.randint(1000, 9000)}, length 0"
        )

    def _syslog_prefix(self) -> str:
        month = datetime.now().strftime("%b")
        return f"{month} {self.random.randint(1, 28):02d} {self._clock()} virtual-lan-tap"

    def _assert_exact_anomalies(self, lines: List[str]) -> None:
        arp_count = sum(ARP_ANOMALY_LINE in line for line in lines)
        token_count = sum(HTTP_TOKEN_LEAK in line for line in lines)
        if arp_count != 1 or token_count != 1:
            raise RuntimeError(f"Expected exactly one ARP anomaly and one HTTP token leak; got {arp_count} and {token_count}.")


class AgenticSiftingPipeline:
    """Read raw text and submit it unchanged to an OpenAI-compatible endpoint."""

    def __init__(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout_seconds: int = 60,
    ) -> None:
        self.provider = (provider or os.getenv("LLM_PROVIDER") or self._detect_provider()).lower()
        self.base_url = (base_url or os.getenv("LLM_BASE_URL") or self._default_base_url(self.provider)).rstrip("/")
        self.api_key = api_key or self._api_key_for_provider(self.provider)
        self.api_url = api_url or os.getenv("LLM_API_URL") or f"{self.base_url}/chat/completions"
        self.model = model or os.getenv("LLM_MODEL") or self._default_model(self.provider)
        self.timeout_seconds = timeout_seconds

        if not self.api_key:
            raise PipelineConfigError(
                "Missing API key. Set OPENAI_API_KEY for provider=openai, OPENROUTER_API_KEY for provider=openrouter, or use provider=ollama."
            )

    def process_stream(self, log_file_path: Path | str) -> str:
        raw_text_block = open(log_file_path, "r", encoding="utf-8").read()
        payload = self._build_api_payload(raw_text_block)
        return self._submit_payload(payload)

    def correct_stream(self, raw_text_block: str, flawed_audit: Dict[str, Any], semantic_errors: List[str]) -> str:
        payload = self._build_api_payload(
            raw_text_block,
            extra_system_instruction=CORRECTION_NUDGE,
            flawed_audit=flawed_audit,
            semantic_errors=semantic_errors,
        )
        return self._submit_payload(payload)

    def _submit_payload(self, payload: Dict[str, Any]) -> str:
        request = urllib.request.Request(
            self.api_url,
            data=json.dumps(payload).encode("utf-8"),
            headers=self._headers(),
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                response_body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise ModelResponseError(f"Model endpoint returned HTTP {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise ModelResponseError(f"Model endpoint request failed: {exc}") from exc

        return self._extract_model_text(response_body)

    def _build_api_payload(
        self,
        raw_text_block: str,
        extra_system_instruction: Optional[str] = None,
        flawed_audit: Optional[Dict[str, Any]] = None,
        semantic_errors: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        system_content = SYSTEM_INSTRUCTIONS
        if extra_system_instruction:
            system_content = f"{SYSTEM_INSTRUCTIONS}\n\n{extra_system_instruction}"

        user_content = raw_text_block
        if flawed_audit is not None:
            user_content = (
                "RAW WIRE DUMP:\n"
                f"{raw_text_block}\n\n"
                "FLAWED JSON AUDIT TO CORRECT:\n"
                f"{json.dumps(flawed_audit, indent=2)}\n\n"
                "SEMANTIC VALIDATION FAILURES:\n"
                f"{json.dumps(semantic_errors or [], indent=2)}"
            )

        payload: Dict[str, Any] = {
            "model": self.model,
            "temperature": 0,
            "response_format": AUDIT_RESPONSE_FORMAT if self.provider == "ollama" else {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_content},
                {"role": "user", "content": user_content},
            ],
        }
        if self.provider == "ollama":
            payload["options"] = {"num_ctx": 4096}
        return payload

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        if self.provider == "openrouter":
            headers["HTTP-Referer"] = os.getenv("OPENROUTER_SITE_URL", "http://localhost")
            headers["X-Title"] = os.getenv("OPENROUTER_APP_TITLE", "Virtual Automated Threat Hunting Console")
        return headers

    def _extract_model_text(self, response_body: str) -> str:
        try:
            parsed = json.loads(response_body)
        except json.JSONDecodeError as exc:
            raise ModelResponseError("Model endpoint did not return valid JSON transport data.") from exc

        try:
            content = parsed["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ModelResponseError("Model response did not include choices[0].message.content.") from exc

        if not isinstance(content, str) or not content.strip():
            raise ModelResponseError("Model response content was empty.")

        # Hardening: Strip potential Markdown code blocks
        cleaned = content.strip()
        if cleaned.startswith("```"):
            # Remove opening backticks and optional language identifier
            cleaned = cleaned.split("\n", 1)[-1]
            if cleaned.endswith("```"):
                cleaned = cleaned.rsplit("```", 1)[0]
        return cleaned.strip()

    @staticmethod
    def _detect_provider() -> str:
        if os.getenv("OLLAMA_HOST") or os.getenv("LLM_BASE_URL"):
            return "ollama"
        if os.getenv("OPENROUTER_API_KEY"):
            return "openrouter"
        if os.getenv("OPENAI_API_KEY"):
            return "openai"
        return "ollama"

    @staticmethod
    def _api_key_for_provider(provider: str) -> Optional[str]:
        if provider == "ollama":
            return os.getenv("OLLAMA_API_KEY", "ollama")
        if provider == "openrouter":
            return os.getenv("OPENROUTER_API_KEY")
        if provider == "openai":
            return os.getenv("OPENAI_API_KEY")
        raise PipelineConfigError("Unsupported provider. Use 'ollama', 'openai', or 'openrouter'.")

    @staticmethod
    def _default_base_url(provider: str) -> str:
        if provider == "ollama":
            return OLLAMA_BASE_URL
        if provider == "openrouter":
            return OPENROUTER_CHAT_COMPLETIONS_URL.rsplit("/chat/completions", 1)[0]
        if provider == "openai":
            return OPENAI_CHAT_COMPLETIONS_URL.rsplit("/chat/completions", 1)[0]
        raise PipelineConfigError("Unsupported provider. Use 'ollama', 'openai', or 'openrouter'.")

    @staticmethod
    def _default_model(provider: str) -> str:
        if provider == "ollama":
            return DEFAULT_OLLAMA_MODEL
        if provider == "openrouter":
            return DEFAULT_OPENROUTER_MODEL
        if provider == "openai":
            return DEFAULT_OPENAI_MODEL
        raise PipelineConfigError("Unsupported provider. Use 'ollama', 'openai', or 'openrouter'.")


class StateDatabase:
    """Validate and append model audits to data/state_db.json."""

    def __init__(self, db_path: Path = STATE_DB_PATH) -> None:
        self.db_path = db_path

    def append_model_response(self, model_response: str, raw_text: str, skip_semantics: bool = False) -> Dict[str, Any]:
        try:
            audit = json.loads(model_response)
        except json.JSONDecodeError as exc:
            raise ModelResponseError("Model response failed json.loads(); persistence aborted.") from exc

        self._validate_audit_schema(audit)
        if not skip_semantics:
            self._validate_audit_semantics(audit, raw_text)

        records = self._read_records()
        record = {
            "record_type": "threat_audit",
            "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "audit": audit,
        }
        records.append(record)
        self._atomic_write(records)
        return audit

    def _read_records(self) -> List[Dict[str, Any]]:
        if not self.db_path.exists() or not self.db_path.read_text(encoding="utf-8").strip():
            return []
        try:
            records = json.loads(self.db_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ModelResponseError(f"Existing database is not valid JSON: {self.db_path}") from exc
        if not isinstance(records, list):
            raise ModelResponseError(f"Existing database must be a JSON array: {self.db_path}")
        return records

    def _atomic_write(self, records: List[Dict[str, Any]]) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=DATA_DIR, delete=False) as tmp:
            json.dump(records, tmp, indent=2)
            tmp.write("\n")
            tmp_path = Path(tmp.name)
        tmp_path.replace(self.db_path)

    def _validate_audit_schema(self, audit: Any) -> None:
        if not isinstance(audit, dict):
            raise ModelResponseError("Audit root must be a JSON object.")
        if set(audit) == {"response"} and "can't assist" in str(audit.get("response", "")).lower():
            raise ModelResponseError("Model returned a refusal wrapper instead of the required audit schema.")

        required_root = {"audit_summary", "detected_nodes", "threat_incidents", "visual_topology_edges"}
        missing_root = required_root - set(audit)
        if missing_root:
            raise ModelResponseError(f"Audit JSON missing root keys: {sorted(missing_root)}")

        self._validate_summary(audit["audit_summary"])
        self._validate_nodes(audit["detected_nodes"])
        self._validate_incidents(audit["threat_incidents"])
        self._validate_edges(audit["visual_topology_edges"])

    def _validate_audit_semantics(self, audit: Dict[str, Any], raw_text: str) -> None:
        facts = self._scan_ground_truth(raw_text)
        summary = audit["audit_summary"]
        incidents = audit["threat_incidents"]
        verdict = str(summary.get("executive_verdict", "")).lower()
        incident_types = {str(incident.get("type")) for incident in incidents}
        incident_severities = {str(incident.get("severity")) for incident in incidents}
        errors: List[str] = []

        # 1. Risk Level & Incident Count
        if (facts["has_arp_anomaly"] or facts["has_leak_anomaly"]) and summary.get("detected_risk_level") != "HIGH":
            errors.append("detected_risk_level must be HIGH when deterministic anomalies exist")

        if len(incidents) < 2:
            errors.append("threat_incidents must contain at least 2 active incident configurations")

        # 2. Verdict Contradiction Check (Prevent 'benign' labels for HIGH risk)
        benign_keywords = ["benign", "no significant", "no security threats", "no threats detected", "safe", "secure"]
        if summary.get("detected_risk_level") == "HIGH" and any(word in verdict for word in benign_keywords):
            errors.append("executive_verdict must not describe the trace as benign or safe when risk level is HIGH")

        # 3. Specific Threat Identification Enforcement
        if facts["has_arp_anomaly"] and "ROUTING_SPOOF" not in incident_types:
            errors.append("missing specific 'ROUTING_SPOOF' incident for the unverified ARP routing update")

        if facts["has_leak_anomaly"] and "PLAINTEXT_DATA_LEAK" not in incident_types:
            errors.append("missing specific 'PLAINTEXT_DATA_LEAK' incident for the port 80 token exposure")

        # 4. Severity Enforcement
        if (facts["has_arp_anomaly"] or facts["has_leak_anomaly"]) and "CRITICAL" not in incident_severities:
            errors.append("detected threat incidents must be marked with CRITICAL severity")

        if errors:
            raise SemanticValidationError(errors, audit)

    @staticmethod
    def _scan_ground_truth(raw_text: str) -> Dict[str, bool]:
        # Implementation Step 1: Deterministic Pre-Scan
        has_arp_anomaly = "unverified" in raw_text
        has_leak_anomaly = "auth_token=" in raw_text or "token=ghp_" in raw_text
        return {
            "has_arp_anomaly": has_arp_anomaly,
            "has_leak_anomaly": has_leak_anomaly,
        }

    def _validate_summary(self, summary: Any) -> None:
        if not isinstance(summary, dict):
            raise ModelResponseError("audit_summary must be an object.")
        expected = {"total_frames_analyzed", "benign_frames_dropped", "detected_risk_level", "executive_verdict"}
        missing = expected - set(summary)
        if missing:
            raise ModelResponseError(f"audit_summary missing keys: {sorted(missing)}")
        if not isinstance(summary["total_frames_analyzed"], int):
            raise ModelResponseError("audit_summary.total_frames_analyzed must be an integer.")
        if not isinstance(summary["benign_frames_dropped"], int):
            raise ModelResponseError("audit_summary.benign_frames_dropped must be an integer.")
        if summary["detected_risk_level"] not in {"LOW", "MEDIUM", "HIGH"}:
            raise ModelResponseError("audit_summary.detected_risk_level is invalid.")
        if not isinstance(summary["executive_verdict"], str):
            raise ModelResponseError("audit_summary.executive_verdict must be a string.")

    def _validate_nodes(self, nodes: Any) -> None:
        if not isinstance(nodes, list):
            raise ModelResponseError("detected_nodes must be an array.")
        required = {"id", "ip_address", "mac_address", "device_type", "vendor_oui", "status"}
        valid_types = {"GATEWAY", "USER_LAPTOP", "TARGET_ENDPOINT", "SUSPICIOUS_PROXIED_NODE", "UNKNOWN"}
        valid_statuses = {"SECURE", "VULNERABLE", "COMPROMISED"}
        for index, node in enumerate(nodes):
            if not isinstance(node, dict):
                raise ModelResponseError(f"detected_nodes[{index}] must be an object.")
            missing = required - set(node)
            if missing:
                raise ModelResponseError(f"detected_nodes[{index}] missing keys: {sorted(missing)}")
            if node["device_type"] not in valid_types:
                raise ModelResponseError(f"detected_nodes[{index}].device_type is invalid.")
            if node["status"] not in valid_statuses:
                raise ModelResponseError(f"detected_nodes[{index}].status is invalid.")

    def _validate_incidents(self, incidents: Any) -> None:
        if not isinstance(incidents, list):
            raise ModelResponseError("threat_incidents must be an array.")
        required = {
            "incident_id",
            "source_node",
            "destination_node",
            "protocol",
            "severity",
            "type",
            "technical_details",
            "remediation_action",
        }
        valid_severities = {"INFO", "WARNING", "CRITICAL"}
        valid_types = {"ROUTING_SPOOF", "PLAINTEXT_DATA_LEAK", "SUSPICIOUS_BEHAVIOR"}
        for index, incident in enumerate(incidents):
            if not isinstance(incident, dict):
                raise ModelResponseError(f"threat_incidents[{index}] must be an object.")
            missing = required - set(incident)
            if missing:
                raise ModelResponseError(f"threat_incidents[{index}] missing keys: {sorted(missing)}")
            if incident["severity"] not in valid_severities:
                raise ModelResponseError(f"threat_incidents[{index}].severity is invalid.")
            if incident["type"] not in valid_types:
                raise ModelResponseError(f"threat_incidents[{index}].type is invalid.")
            if HTTP_TOKEN_LEAK.split("token=", 1)[1].split(" ", 1)[0] in str(incident.get("technical_details", "")):
                raise ModelResponseError("Model response repeated a raw token in technical_details.")

    def _validate_edges(self, edges: Any) -> None:
        if not isinstance(edges, list):
            raise ModelResponseError("visual_topology_edges must be an array.")
        valid_relationships = {"ROUTED_THROUGH", "ATTACKING", "LEAKING_TO", "STANDARD_TRAFFIC"}
        for index, edge in enumerate(edges):
            if not isinstance(edge, dict):
                raise ModelResponseError(f"visual_topology_edges[{index}] must be an object.")
            missing = {"from", "to", "relationship"} - set(edge)
            if missing:
                raise ModelResponseError(f"visual_topology_edges[{index}] missing keys: {sorted(missing)}")
            if edge["relationship"] not in valid_relationships:
                raise ModelResponseError(f"visual_topology_edges[{index}].relationship is invalid.")


def run_pipeline(args: argparse.Namespace) -> Dict[str, Any]:
    print("--- OPENCLUE: OPEN-SOURCE THREAT DETECTION & TRIAGE PLATFORM ---", file=sys.stderr)
    log_path = Path(args.log_path)
    
    if args.stdin:
        print("[*] Reading raw telemetry from stdin...", file=sys.stderr)
        raw_text = sys.stdin.read()
        if not raw_text.strip():
            raise ValueError("No data received on stdin.")
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        log_path.write_text(raw_text, encoding="utf-8")
        print(f"[+] Stdin captured and written to {log_path} ({len(raw_text.splitlines())} lines)", file=sys.stderr)
    else:
        print(f"[*] Initializing telemetry generation (seed={args.seed or 'random'})...", file=sys.stderr)
        generator = RawTelemetryGenerator(
            output_path=log_path,
            benign_line_count=args.benign_lines,
            seed=args.seed,
        )
        generator.generate()
        print(f"[+] Synthetic logs written to {log_path} ({args.benign_lines + 2} lines)", file=sys.stderr)

    if args.generate_only:
        return {
            "status": "generated",
            "raw_wire_dump": str(log_path),
            "state_db": str(Path(args.db_path)),
            "analysis_executed": False,
        }

    print(f"[*] Connecting to {args.provider} ({args.model or 'default model'})...", file=sys.stderr)
    pipeline = AgenticSiftingPipeline(
        provider=args.provider,
        model=args.model,
        base_url=args.base_url,
        api_url=args.api_url,
        api_key=args.api_key,
        timeout_seconds=args.timeout,
    )
    raw_text = log_path.read_text(encoding="utf-8")
    database = StateDatabase(Path(args.db_path))

    print("[*] Analyzing raw telemetry stream... (this may take 1-2 minutes on local hardware)", file=sys.stderr)
    model_response = pipeline.process_stream(log_path)
    
    # Iterative Self-Healing Loop (Up to 3 attempts)
    max_retries = 3
    attempts = 0
    self_corrected = False
    last_audit = None

    while attempts <= max_retries:
        attempts += 1
        try:
            print(f"[*] Validating model response (Attempt {attempts}/{max_retries + 1})...", file=sys.stderr)
            audit = database.append_model_response(model_response, raw_text, skip_semantics=args.stdin)
            print("[+] Audit successfully validated and persisted.", file=sys.stderr)
            return {
                "status": "completed",
                "raw_wire_dump": str(log_path),
                "state_db": str(Path(args.db_path)),
                "provider": pipeline.provider,
                "model": pipeline.model,
                "self_corrected": self_corrected,
                "audit": audit,
            }
        except SemanticValidationError as exc:
            self_corrected = True
            last_audit = exc.audit
            if attempts > max_retries:
                print(f"[!] Maximum retries reached. Final validation failed: {'; '.join(exc.errors)}", file=sys.stderr)
                raise
            
            print(f"[!] Semantic validation failed: {'; '.join(exc.errors)}", file=sys.stderr)
            print(f"[*] Triggering self-healing correction loop (Retry {attempts})...", file=sys.stderr)
            model_response = pipeline.correct_stream(raw_text, exc.audit, exc.errors)
        except ModelResponseError as exc:
            print(f"[!] Structural/Schema error: {exc}", file=sys.stderr)
            raise

    # Fallback (should not be reached due to raise in loop)
    return {"status": "failed", "error": "Maximum retries exceeded without validation success."}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the Virtual Automated Threat Hunting Console backend pipeline.")
    parser.add_argument("--provider", choices=["ollama", "openai", "openrouter"], help="LLM provider. Defaults to local Ollama when no cloud key is configured.")
    parser.add_argument("--model", help="Model name. Defaults to LLM_MODEL, then a provider-specific default.")
    parser.add_argument("--base-url", help="OpenAI-compatible base URL. Defaults to http://localhost:11434/v1 for Ollama.")
    parser.add_argument("--api-url", help="Override the OpenAI-compatible chat completions endpoint URL.")
    parser.add_argument("--api-key", help="API key override. Prefer environment variables for normal use.")
    parser.add_argument("--timeout", type=int, default=600, help="Model request timeout in seconds (default: 600).")
    parser.add_argument("--seed", type=int, help="Optional generator seed for reproducible emulated telemetry.")
    parser.add_argument("--benign-lines", type=int, default=128, help="Number of benign raw lines before anomaly injection.")
    parser.add_argument("--log-path", default=str(RAW_WIRE_DUMP_PATH), help="Output path for raw wire dump.")
    parser.add_argument("--db-path", default=str(STATE_DB_PATH), help="Local JSON database path.")
    parser.add_argument("--generate-only", action="store_true", help="Only generate raw telemetry; do not call the model.")
    parser.add_argument("--stdin", action="store_true", help="Read raw telemetry from standard input instead of generating it.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        result = run_pipeline(args)
    except (PipelineConfigError, ModelResponseError, OSError, ValueError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, indent=2), file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
