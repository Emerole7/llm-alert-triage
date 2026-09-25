"""Threat intel enrichment: AbuseIPDB for IPs, VirusTotal for IPs and file hashes.

Only public IPs are looked up. Results are cached in memory so repeated
alerts from the same source do not burn free-tier quota (VirusTotal free
allows 4 requests per minute).
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, Optional

import requests

log = logging.getLogger(__name__)
TIMEOUT = 10


def is_public_ip(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


class Enricher:
    def __init__(self, abuseipdb_key: str = "", virustotal_key: str = ""):
        self.abuse_key = abuseipdb_key
        self.vt_key = virustotal_key
        self._cache: Dict[str, Any] = {}

    def _cached(self, key: str, fn):
        if key not in self._cache:
            try:
                self._cache[key] = fn()
            except requests.RequestException as exc:
                log.warning("enrichment failed for %s: %s", key, exc)
                return {"error": "lookup_failed"}
        return self._cache[key]

    def abuseipdb(self, ip: str) -> Dict[str, Any]:
        def call():
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self.abuse_key, "Accept": "application/json"},
                timeout=TIMEOUT,
            )
            r.raise_for_status()
            d = r.json().get("data", {})
            return {
                "abuse_confidence_score": d.get("abuseConfidenceScore"),
                "total_reports": d.get("totalReports"),
                "country": d.get("countryCode"),
                "isp": d.get("isp"),
                "usage_type": d.get("usageType"),
                "is_tor": d.get("isTor"),
            }
        return self._cached(f"abuse:{ip}", call)

    def virustotal_ip(self, ip: str) -> Dict[str, Any]:
        def call():
            r = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self.vt_key},
                timeout=TIMEOUT,
            )
            if r.status_code == 429:
                raise requests.RequestException("VirusTotal rate limit")
            r.raise_for_status()
            attrs = r.json().get("data", {}).get("attributes", {})
            return {
                "last_analysis_stats": attrs.get("last_analysis_stats"),
                "reputation": attrs.get("reputation"),
                "as_owner": attrs.get("as_owner"),
            }
        return self._cached(f"vtip:{ip}", call)

    def virustotal_hash(self, sha256: str) -> Dict[str, Any]:
        def call():
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": self.vt_key},
                timeout=TIMEOUT,
            )
            if r.status_code == 404:
                return {"known_to_virustotal": False}
            if r.status_code == 429:
                raise requests.RequestException("VirusTotal rate limit")
            r.raise_for_status()
            attrs = r.json().get("data", {}).get("attributes", {})
            return {
                "known_to_virustotal": True,
                "last_analysis_stats": attrs.get("last_analysis_stats"),
                "meaningful_name": attrs.get("meaningful_name"),
            }
        return self._cached(f"vthash:{sha256}", call)

    def enrich(self, source: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        data = source.get("data", {}) or {}
        ip = data.get("srcip") or (data.get("win", {}) or {}).get("eventdata", {}).get("ipAddress")
        if ip:
            if not is_public_ip(ip):
                out["srcip"] = {"ip": ip, "note": "private or reserved address, not looked up"}
            else:
                intel: Dict[str, Any] = {"ip": ip}
                if self.abuse_key:
                    intel["abuseipdb"] = self.abuseipdb(ip)
                if self.vt_key:
                    intel["virustotal"] = self.virustotal_ip(ip)
                out["srcip"] = intel
        sha = (source.get("syscheck", {}) or {}).get("sha256_after")
        if sha and self.vt_key:
            out["file_hash"] = {"sha256": sha, "virustotal": self.virustotal_hash(sha)}
        return out
