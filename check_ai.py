"""Checks your AI setup and tells you what is wrong.   Run from the project folder:  python check_ai.py
It never prints your full key."""
from pathlib import Path

import config
import rag


def env_file_value(name):
    p = Path(".env")
    if not p.exists():
        return None
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith(name + "="):
            return line.split("=", 1)[1].strip()
    return ""


def mask(k):
    return "(empty)" if not k else f"{k[:4]}...{k[-4:]}  ({len(k)} characters)"


print(f"Folder   : {Path('.').resolve()}")
print(f".env file: {'found' if Path('.env').exists() else 'NOT FOUND in this folder'}")
print(f"Provider : {config.LLM_PROVIDER}   Model: {config.LLM_MODEL}")
if config.LLM_PROVIDER == "offline":
    raise SystemExit("No AI key is being read. Put GROQ_API_KEY=... in .env (same folder as main.py) and run again.")

name = "GROQ_API_KEY" if config.LLM_PROVIDER == "groq" else "GOOGLE_API_KEY"
key = config.GROQ_API_KEY if config.LLM_PROVIDER == "groq" else config.GOOGLE_API_KEY
print(f"Key used : {mask(key)}")
raw = env_file_value(name)
if raw is not None and raw.strip("'\" ") != key:
    print(f"PROBLEM  : the key in .env is different from the key the app is using. An older key set in your terminal or\n"
          f"           Windows environment is overriding .env. In PowerShell run:  Remove-Item Env:{name}\n"
          f"           then close and reopen the terminal.")
if config.LLM_PROVIDER == "groq" and not key.startswith("gsk_"):
    print("PROBLEM  : Groq keys start with gsk_ . This does not look like a Groq key.")
if any(c in key for c in " \"'#"):
    print("PROBLEM  : the key contains a space, quote or # character. Remove it from .env.")

print("\nTesting a real request...")
try:
    print("SUCCESS  :", rag._ask_llm("Reply with the single word: ready"))
except Exception as e:
    print("FAILED   :", e)
    if "401" in str(e):
        print("           401 means the provider rejected the key. Create a new key and paste it again.")
