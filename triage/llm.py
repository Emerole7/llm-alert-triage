"""LLM backends. Each returns the raw dict the model produced for the triage schema."""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict

import requests

from .schema import TRIAGE_JSON_SCHEMA

log = logging.getLogger(__name__)

TOOL = {
    "name": "submit_triage",
    "description": "Submit the triage verdict for this alert.",
    "input_schema": TRIAGE_JSON_SCHEMA,
}


class AnthropicBackend:
    name = "anthropic"

    def __init__(self, api_key: str, model: str):
        import anthropic  # imported here so other backends work without the package

        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY is empty")
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def triage(self, system: str, user: str) -> Dict[str, Any]:
        resp = self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=system,
            tools=[TOOL],
            tool_choice={"type": "tool", "name": "submit_triage"},
            messages=[{"role": "user", "content": user}],
        )
        for block in resp.content:
            if block.type == "tool_use" and block.name == "submit_triage":
                return dict(block.input)
        raise ValueError("model did not call submit_triage")


class OllamaBackend:
    name = "ollama"

    def __init__(self, url: str, model: str):
        self.url = url
        self.model = model

    def triage(self, system: str, user: str) -> Dict[str, Any]:
        r = requests.post(
            f"{self.url}/api/chat",
            json={
                "model": self.model,
                "stream": False,
                "format": TRIAGE_JSON_SCHEMA,
                "options": {"temperature": 0},
                "messages": [
                    {"role": "system", "content": system.replace("through the submit_triage tool", "as JSON")},
                    {"role": "user", "content": user},
                ],
            },
            timeout=300,
        )
        r.raise_for_status()
        return json.loads(r.json()["message"]["content"])


class MockBackend:
    """Rule-of-thumb stand-in for testing the pipeline without an API key."""

    name = "mock"
    model = "mock"

    def triage(self, system: str, user: str) -> Dict[str, Any]:
        level_match = re.search(r'"level":\s*(\d+)', user)
        level = int(level_match.group(1)) if level_match else 5
        verdict = "needs_investigation" if level >= 7 else "benign_true_positive"
        return {
            "verdict": verdict,
            "confidence": 0.5,
            "priority": "P2" if level >= 10 else "P3" if level >= 7 else "P4",
            "mitre_techniques": [],
            "summary": f"Mock triage of a level {level} alert.",
            "reasoning": "Mock backend: verdict chosen from rule level only.",
            "recommended_actions": ["Review the alert manually."],
            "injection_suspected": False,
        }


def make_backend(settings) -> Any:
    if settings.llm_backend == "anthropic":
        return AnthropicBackend(settings.anthropic_api_key, settings.anthropic_model)
    if settings.llm_backend == "ollama":
        return OllamaBackend(settings.ollama_url, settings.ollama_model)
    if settings.llm_backend == "mock":
        return MockBackend()
    raise ValueError(f"unknown LLM_BACKEND: {settings.llm_backend}")
