"""Terminal demo of the key requirement. No server needed. Run: python demo_cli.py"""
import os, tempfile
os.environ["VAULT_DATA_DIR"] = tempfile.mkdtemp(prefix="vaultmind_demo_")
os.environ["GOOGLE_API_KEY"] = ""
os.environ["GROQ_API_KEY"] = ""
os.environ["LLM_PROVIDER"] = ""
import rag

rag.index_document(1, "salaries.txt", "admin", "CONFIDENTIAL. Ali earns 250000 PKR per month. Sara earns 310000 PKR per month.")
rag.index_document(2, "leave_policy.txt", "standard", "Every employee gets 20 days of annual leave and 10 days of sick leave.")

for role, q in [("standard", "What is Ali's salary?"), ("admin", "What is Ali's salary?"),
                ("standard", "How many days of annual leave do I get?")]:
    r = rag.answer_question(q, role)
    print(f"[{role.upper():8}] Q: {q}\n           A: {r['answer']}\n           Sources: {r['sources']}")
    print("           SECURITY ALERT: blocked attempt logged for admins\n" if r["blocked"] else "")
print("Upload scan on 'The server password is: Delta-77X' ->", rag.scan_sensitive("The server password is: Delta-77X"))
