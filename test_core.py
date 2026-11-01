"""Engine tests: need only the Python standard library + cryptography/python-docx. Run: python test_core.py"""
import os
import sqlite3
import tempfile
import unittest

os.environ.setdefault("VAULT_DATA_DIR", tempfile.mkdtemp(prefix="vaultmind_core_"))
os.environ.setdefault("GOOGLE_API_KEY", "")
os.environ.setdefault("GROQ_API_KEY", "")
os.environ.setdefault("LLM_PROVIDER", "")

import config
import rag
from encryption import decrypt_bytes, encrypt_bytes

SALARIES = "Salary sheet (CONFIDENTIAL). Ali earns 250000 PKR per month. Sara earns 310000 PKR per month."
POLICY = "Leave policy: every employee gets 20 days of annual leave and 10 days of sick leave per year."


class CoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rag.index_document(9001, "salaries.txt", "admin", SALARIES)
        rag.index_document(9002, "leave_policy.txt", "standard", POLICY)

    @classmethod
    def tearDownClass(cls):
        rag.delete_document(9001)
        rag.delete_document(9002)

    def test_encryption_roundtrip(self):
        self.assertEqual(decrypt_bytes(encrypt_bytes(b"hello")), b"hello")

    def test_standard_user_cannot_see_confidential(self):
        r = rag.answer_question("What is Ali's salary?", "standard")
        self.assertEqual(r["answer"], rag.REFUSAL)
        self.assertEqual(r["sources"], [])

    def test_admin_can_see_confidential(self):
        r = rag.answer_question("What is Ali's salary?", "admin")
        self.assertIn("250000", r["answer"])
        self.assertIn("salaries.txt", r["sources"])

    def test_standard_user_gets_public_answer_with_citation(self):
        r = rag.answer_question("How many days of annual leave?", "standard")
        self.assertIn("20 days", r["answer"])
        self.assertEqual(r["sources"], ["leave_policy.txt"])

    def test_unrelated_question_refused(self):
        self.assertTrue(rag.answer_question("quantum chromodynamics", "admin")["answer"].startswith(rag.REFUSAL))

    def test_chunks_encrypted_at_rest(self):
        raw = b"".join(bytes(r[0]) for r in sqlite3.connect(config.DB_PATH).execute(
            "SELECT text_enc FROM chunks WHERE doc_id IN (9001, 9002)"))
        self.assertNotIn(b"250000", raw)
        self.assertNotIn(b"annual leave", raw)

    def test_docx_parsing(self):
        import docx, io
        d = docx.Document(); d.add_paragraph("Parking is free for staff."); buf = io.BytesIO(); d.save(buf)
        self.assertIn("Parking is free", rag.extract_text("p.docx", buf.getvalue()))

    def test_bad_file_types_rejected(self):
        with self.assertRaises(ValueError):
            rag.extract_text("virus.exe", b"MZ")
        with self.assertRaises(ValueError):
            rag.extract_text("empty.txt", b"   ")

    def test_chunking_splits_long_text(self):
        self.assertGreater(len(rag.chunk_text("word " * 600)), 3)

    def test_filename_is_searchable(self):
        rag.index_document(9004, "Resume_Test.txt", "standard", "Skills: video editing and photography.")
        r = rag.answer_question("what is in this resume", "standard")
        rag.delete_document(9004)
        self.assertIn("video editing", r["answer"])

    def test_pdf_style_broken_spacing(self):
        rag.index_document(9005, "cv.txt", "standard", "WO R K E X P E R I E N C E  M e h r an St u dio  Video Editor")
        r = rag.answer_question("Is experience provided?", "standard")
        rag.delete_document(9005)
        self.assertIn("Video Editor", r["answer"])

    def test_sensitive_scan(self):
        self.assertIn("password or secret", rag.scan_sensitive("The server password for the portal is: Delta-77X"))
        self.assertIn("salary or pay figures", rag.scan_sensitive("Ali earns 250000 PKR per month"))
        self.assertIn("national ID number", rag.scan_sensitive("CNIC 41234-1234567-1"))
        self.assertIn("card number", rag.scan_sensitive("Card 4111 1111 1111 1111 exp 12/29"))
        self.assertEqual(rag.scan_sensitive("Employees get 20 days of annual leave."), [])
        self.assertNotIn("card number", rag.scan_sensitive("Order number 1234 5678 9012 3456"))

    def test_blocked_attempt_flag(self):
        self.assertTrue(rag.answer_question("What is Ali's salary?", "standard")["blocked"])
        self.assertFalse(rag.answer_question("What is Ali's salary?", "admin")["blocked"])
        self.assertFalse(rag.answer_question("How many days of annual leave?", "standard")["blocked"])

    def test_single_file_scope(self):
        r = rag.answer_question("annual leave", "admin", doc_id=9002)
        self.assertEqual(r["sources"], ["leave_policy.txt"])
        self.assertTrue(rag.answer_question("annual leave", "admin", doc_id=9001)["answer"].startswith(rag.REFUSAL))

    def test_scope_cannot_bypass_roles(self):
        r = rag.answer_question("What is Ali's salary?", "standard", doc_id=9001)   # admin-only file
        self.assertEqual(r["answer"], rag.REFUSAL)
        self.assertTrue(r["blocked"])

    def test_set_access_moves_chunks(self):
        rag.index_document(9006, "memo.txt", "standard", "The team picnic is on Friday.")
        self.assertIn("Friday", rag.answer_question("When is the picnic?", "standard")["answer"])
        rag.set_access(9006, "admin")
        self.assertEqual(rag.answer_question("When is the picnic?", "standard")["answer"], rag.REFUSAL)
        rag.delete_document(9006)

    def test_department_access(self):
        rag.index_document(9007, "finance_limits.txt", "dept:Finance", "The budget approval limit is 5000 dollars.")
        q = "What is the budget approval limit?"
        self.assertEqual(rag.answer_question(q, "standard")["answer"], rag.REFUSAL)                  # no department
        self.assertEqual(rag.answer_question(q, "standard", dept="HR")["answer"], rag.REFUSAL)      # wrong department
        self.assertTrue(rag.answer_question(q, "standard", dept="HR")["blocked"])
        self.assertIn("5000", rag.answer_question(q, "standard", dept="Finance")["answer"])         # right department
        self.assertFalse(rag.answer_question(q, "standard", dept="Finance")["blocked"])
        self.assertIn("5000", rag.answer_question(q, "admin")["answer"])                            # admins see all
        rag.delete_document(9007)

    def _with_fake_llm(self, fake_post):
        saved = (config.LLM_PROVIDER, config.GROQ_API_KEY, rag.requests.post)
        config.LLM_PROVIDER, config.GROQ_API_KEY, rag.requests.post = "groq", "test-key", fake_post
        try:
            return rag.answer_question("What is Ali's salary?", "admin")
        finally:
            config.LLM_PROVIDER, config.GROQ_API_KEY, rag.requests.post = saved

    def test_groq_provider(self):
        seen = {}

        class Resp:
            status_code = 200
            def json(self):
                return {"choices": [{"message": {"content": "<think>notes</think>Ali earns 250000 PKR."}}]}

        def fake(url, headers=None, json=None, timeout=None):
            seen.update(url=url, auth=headers["Authorization"], model=json["model"], prompt=json["messages"][0]["content"])
            return Resp()

        r = self._with_fake_llm(fake)
        self.assertEqual(r["answer"], "Ali earns 250000 PKR.")
        self.assertEqual(r["mode"], "groq")
        self.assertIn("api.groq.com/openai/v1/chat/completions", seen["url"])
        self.assertEqual(seen["auth"], "Bearer test-key")
        self.assertIn("250000", seen["prompt"])          # the passage reached the model

    def test_groq_error_shows_reason_and_falls_back(self):
        class Resp:
            status_code = 400
            text = ""
            def json(self):
                return {"error": {"message": "The model has been decommissioned"}}

        r = self._with_fake_llm(lambda *a, **k: Resp())
        self.assertIn("HTTP 400", r["answer"])
        self.assertIn("decommissioned", r["answer"])
        self.assertIn("250000", r["answer"])             # still shows the matching passage

    def test_admin_tip_only_for_admins(self):
        self.assertIn("Tip", rag.answer_question("quantum chromodynamics", "admin")["answer"])
        self.assertEqual(rag.answer_question("quantum chromodynamics", "standard")["answer"], rag.REFUSAL)

    def test_overview_covers_each_document(self):
        names = {h["filename"] for h in rag.overview("admin")}
        self.assertTrue({"salaries.txt", "leave_policy.txt"} <= names)
        self.assertEqual({h["filename"] for h in rag.overview("standard")}, {"leave_policy.txt"})

    def test_delete_removes_chunks(self):
        rag.index_document(9003, "temp.txt", "standard", "The cafeteria opens at nine.")
        self.assertIn("nine", rag.answer_question("When does the cafeteria open?", "standard")["answer"])
        rag.delete_document(9003)
        self.assertEqual(rag.answer_question("When does the cafeteria open?", "standard")["answer"], rag.REFUSAL)


if __name__ == "__main__":
    unittest.main(verbosity=2)
