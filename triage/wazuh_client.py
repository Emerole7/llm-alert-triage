"""Minimal client for the Wazuh indexer (OpenSearch REST API)."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import requests
import urllib3

log = logging.getLogger(__name__)

RESULTS_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "alert_timestamp": {"type": "date"},
            "alert_id": {"type": "keyword"},
            "rule_id": {"type": "keyword"},
            "rule_level": {"type": "integer"},
            "rule_description": {"type": "text"},
            "rule_groups": {"type": "keyword"},
            "rule_mitre": {"type": "keyword"},
            "agent_name": {"type": "keyword"},
            "srcip": {"type": "keyword"},
            "verdict": {"type": "keyword"},
            "priority": {"type": "keyword"},
            "confidence": {"type": "float"},
            "mitre_techniques": {"type": "keyword"},
            "summary": {"type": "text"},
            "reasoning": {"type": "text"},
            "recommended_actions": {"type": "text"},
            "injection_suspected": {"type": "boolean"},
            "injection_patterns": {"type": "keyword"},
            "guardrail_overrides": {"type": "keyword"},
            "llm_backend": {"type": "keyword"},
            "llm_model": {"type": "keyword"},
            "latency_ms": {"type": "integer"},
            "error": {"type": "keyword"},
        }
    }
}


class WazuhIndexer:
    def __init__(self, url: str, user: str, password: str, ca_cert: Optional[str], verify_tls: bool):
        self.url = url
        self.session = requests.Session()
        self.session.auth = (user, password)
        self.session.headers["Content-Type"] = "application/json"
        if not verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self.session.verify = False
            log.warning("TLS verification disabled. Lab use only.")
        elif ca_cert:
            self.session.verify = ca_cert

    def ping(self) -> Dict[str, Any]:
        r = self.session.get(self.url, timeout=10)
        r.raise_for_status()
        return r.json()

    def fetch_alerts_since(self, index: str, since_ms: int, min_level: int, size: int) -> List[Dict[str, Any]]:
        body = {
            "size": size,
            "sort": [{"timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"timestamp": {"gte": since_ms, "format": "epoch_millis"}}},
                        {"range": {"rule.level": {"gte": min_level}}},
                    ]
                }
            },
        }
        r = self.session.post(f"{self.url}/{index}/_search", json=body, timeout=30)
        r.raise_for_status()
        return r.json().get("hits", {}).get("hits", [])

    def count_related(self, index: str, rule_id: str, srcip: Optional[str], hours: int = 1) -> int:
        filters: List[Dict[str, Any]] = [
            {"term": {"rule.id": rule_id}},
            {"range": {"timestamp": {"gte": f"now-{hours}h"}}},
        ]
        if srcip:
            filters.append({"term": {"data.srcip": srcip}})
        r = self.session.post(
            f"{self.url}/{index}/_count", json={"query": {"bool": {"filter": filters}}}, timeout=15
        )
        if r.status_code != 200:
            return -1
        return int(r.json().get("count", -1))

    def ensure_results_index(self, index: str) -> None:
        r = self.session.head(f"{self.url}/{index}", timeout=10)
        if r.status_code == 200:
            return
        r = self.session.put(f"{self.url}/{index}", json=RESULTS_MAPPING, timeout=15)
        if r.status_code not in (200, 201):
            log.error("could not create index %s: %s", index, r.text[:300])
            r.raise_for_status()
        log.info("created results index %s", index)

    def index_result(self, index: str, doc: Dict[str, Any]) -> None:
        r = self.session.post(f"{self.url}/{index}/_doc", json=doc, timeout=15)
        if r.status_code not in (200, 201):
            log.error("index write failed: %s", r.text[:300])
