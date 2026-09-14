import os
import httpx

API_KEY = os.environ.get("LLM_API_KEY", "dummy-test-key")

models_to_test = [
    "google/gemma-4-31b-it:free",
    "google/gemma-4-26b-a4b-it:free",
    "nvidia/nemotron-3.5-lightning:free",
    "nex-agi/nex-n2.5-pro:free",
    "liquid/lfm-2.5-2.6b:free",
    "meta-llama/llama-3-8b-instruct:free",
    "google/gemma-2-9b-it:free",
]

for model in models_to_test:
    print(f"Testing {model}...")
    try:
        r = httpx.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {API_KEY}"},
            json={
                "model": model,
                "messages": [{"role": "user", "content": 'Respond with ONLY JSON: {"status": "ok", "threat_category": "PHISHING"}'}],
                "max_tokens": 100
            },
            timeout=20.0
        )
        print(f"  Status: {r.status_code}")
        if r.status_code == 200:
            print(f"  Output: {r.json()['choices'][0]['message']['content']}")
            print(f"  ==> SUCCESS WITH {model}!\n")
            break
        else:
            print(f"  Error: {r.text[:200]}\n")
    except Exception as e:
        print(f"  Exception: {e}\n")
