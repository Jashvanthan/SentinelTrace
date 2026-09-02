"""MCP Tool: AI Threat Classification (credential-free)"""
from __future__ import annotations

import json
import os
from typing import Any


async def classify_threat_context(context: dict[str, Any]) -> dict[str, Any]:
    """
    Classify email threat using LLM.
    SECURITY: Only sanitized metadata is used. No credentials ever passed.
    """
    api_key = os.getenv("LLM_API_KEY", "")
    if not api_key:
        return {
            "threat_category": "UNKNOWN",
            "severity": "MEDIUM",
            "confidence_score": 0.0,
            "reasoning": "AI classification unavailable: LLM_API_KEY not set",
            "key_indicators": [],
        }

    # Sanitize — strip any credential-like keys
    forbidden = {"password", "secret", "token", "key", "credential", "auth"}
    safe_context = {
        k: v for k, v in context.items()
        if not any(f in k.lower() for f in forbidden)
    }

    # Truncate body snippet
    if "body_snippet" in safe_context:
        safe_context["body_snippet"] = str(safe_context["body_snippet"])[:2000]

    system_prompt = (
        "You are a cybersecurity threat analyst. Classify the email threat based on the provided "
        "metadata. Return ONLY valid JSON with fields: "
        "threat_category, severity, confidence_score (0.0-1.0), reasoning, key_indicators."
    )

    try:
        import httpx
        base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")
        model = os.getenv("CLASSIFIER_MODEL", "gpt-4o-mini")

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{base_url}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": json.dumps(safe_context)},
                    ],
                    "response_format": {"type": "json_object"},
                    "max_tokens": 512,
                    "temperature": 0.1,
                },
            )
            resp.raise_for_status()
            raw = resp.json()["choices"][0]["message"]["content"]
            return json.loads(raw)
    except Exception as e:
        return {
            "threat_category": "UNKNOWN",
            "severity": "MEDIUM",
            "confidence_score": 0.0,
            "reasoning": f"Classification error: {e}",
            "key_indicators": [],
        }
