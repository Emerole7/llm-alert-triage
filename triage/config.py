"""Runtime settings loaded from .env."""
from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None or val == "":
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    indexer_url: str
    indexer_user: str
    indexer_pass: str
    ca_cert: str | None
    verify_tls: bool
    alerts_index: str
    results_index: str
    min_rule_level: int
    poll_seconds: int
    lookback_minutes: int
    batch_size: int
    llm_backend: str
    anthropic_api_key: str
    anthropic_model: str
    ollama_url: str
    ollama_model: str
    abuseipdb_key: str
    virustotal_key: str
    state_file: str
    output_jsonl: str
    high_severity_level: int


def load_settings() -> Settings:
    ca = os.getenv("WAZUH_CA_CERT", "").strip() or None
    return Settings(
        indexer_url=os.getenv("WAZUH_INDEXER_URL", "https://127.0.0.1:9200").rstrip("/"),
        indexer_user=os.getenv("WAZUH_INDEXER_USER", "admin"),
        indexer_pass=os.getenv("WAZUH_INDEXER_PASS", ""),
        ca_cert=ca,
        verify_tls=_bool("WAZUH_VERIFY_TLS", True),
        alerts_index=os.getenv("WAZUH_ALERTS_INDEX", "wazuh-alerts-*"),
        results_index=os.getenv("RESULTS_INDEX", "llm-triage"),
        min_rule_level=int(os.getenv("MIN_RULE_LEVEL", "5")),
        poll_seconds=int(os.getenv("POLL_SECONDS", "30")),
        lookback_minutes=int(os.getenv("LOOKBACK_MINUTES", "60")),
        batch_size=int(os.getenv("BATCH_SIZE", "25")),
        llm_backend=os.getenv("LLM_BACKEND", "anthropic").lower(),
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", ""),
        anthropic_model=os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001"),
        ollama_url=os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/"),
        ollama_model=os.getenv("OLLAMA_MODEL", "llama3.1:8b"),
        abuseipdb_key=os.getenv("ABUSEIPDB_API_KEY", ""),
        virustotal_key=os.getenv("VIRUSTOTAL_API_KEY", ""),
        state_file=os.getenv("STATE_FILE", ".triage_state.json"),
        output_jsonl=os.getenv("OUTPUT_JSONL", "output/triage_results.jsonl"),
        high_severity_level=int(os.getenv("HIGH_SEVERITY_LEVEL", "12")),
    )
