"""Runs before tests: isolated temp data dir, offline mode, known admin account."""
import os
import tempfile

os.environ["VAULT_DATA_DIR"] = tempfile.mkdtemp(prefix="vaultmind_test_")
os.environ["GOOGLE_API_KEY"] = ""          # force offline mode (no network needed)
os.environ["GROQ_API_KEY"] = ""
os.environ["LLM_PROVIDER"] = ""
os.environ["ADMIN_USERNAME"] = "boss"
os.environ["ADMIN_PASSWORD"] = "BossPass123"
