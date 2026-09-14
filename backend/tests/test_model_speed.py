import os
import httpx
import time

API_KEY = os.environ.get("LLM_API_KEY", "dummy-test-key")

models = [
    "liquid/lfm-2.5-2.6b:free",
    "nex-agi/nex-n2.5-mini:free",
    "nex-agi/nex-n2.5-pro:free",
    "cohere/north-mini-code:free",
    "thinkingmachines/inkling-small:free",
    "nvidia/nemotron-3.5-lightning:free",
]

for m in models:
    t0 = time.time()
    try:
        r = httpx.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {API_KEY}"},
            json={
                "model": m,
                "messages": [{"role": "user", "content": 'Respond with JSON ONLY: {"status": "ok", "threat_category": "PHISHING", "confidence_score": 0.9}'}],
                "max_tokens": 150
            },
            timeout=15.0
        )
        elapsed = time.time() - t0
        print(f"[{elapsed:.2f}s] {m} -> Status {r.status_code}")
        if r.status_code == 200:
            print(f"   Output: {r.json()['choices'][0]['message']['content'][:100]}")
    except Exception as e:
        print(f"[{time.time()-t0:.2f}s] {m} -> Error: {e}")
