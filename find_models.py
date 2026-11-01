"""Lists the AI models your key can use.   Run:  python find_models.py
Uses the provider set in .env (LLM_PROVIDER, or whichever key is filled in)."""
import requests

import config

if config.LLM_PROVIDER == "groq":
    r = requests.get("https://api.groq.com/openai/v1/models",
                     headers={"Authorization": "Bearer " + config.GROQ_API_KEY, "User-Agent": "VaultMind/1.0"}, timeout=20)
    if r.status_code != 200:
        raise SystemExit(f"Groq error {r.status_code}: {r.text[:200]}")
    skip = ("whisper", "tts", "guard", "embed", "orpheus", "playai")
    for m in sorted(x["id"] for x in r.json().get("data", [])):
        if not any(k in m.lower() for k in skip):
            print(m)
    print("\nPut one of these names in GROQ_MODEL in your .env file.")
elif config.LLM_PROVIDER == "gemini":
    r = requests.get("https://generativelanguage.googleapis.com/v1beta/models",
                     headers={"x-goog-api-key": config.GOOGLE_API_KEY}, timeout=20)
    if r.status_code != 200:
        raise SystemExit(f"Gemini error {r.status_code}: {r.text[:200]}")
    for m in r.json().get("models", []):
        if "flash" in m["name"] and "generateContent" in m.get("supportedGenerationMethods", []):
            print(m["name"].replace("models/", ""))
    print("\nPut one of these names in GEMINI_MODEL in your .env file.")
else:
    raise SystemExit("No AI key found. Put GROQ_API_KEY (or GOOGLE_API_KEY) in your .env file first.")
