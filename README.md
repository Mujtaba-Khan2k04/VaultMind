# VaultMind: Secure AI Document Search

**Ask questions about private company documents in plain English, and only ever get answers from files you are allowed to read.**

VaultMind is an AI-powered document search portal built around one idea: employees should get fast answers from internal files **without** pasting confidential data into public AI tools. Access rules are enforced on the server, files and searchable text are encrypted on disk, and every action is written to an audit log.

> **Made as a project during the Cybersecurity Fundamentals Course bootcamp at Bano Qabil, Pakistan.**
> It is an educational project and has not had a professional security audit.

---

## Features

**Search and AI**
- Ask in plain English and get an answer with the **source file names** it came from
- Search **all documents at once**, or pick **a single file** to ask about
- Reads **PDF, DOCX, TXT, Markdown and CSV** files
- Retrieval-augmented generation (RAG): the AI answers only from passages retrieved from your files, and says so when it cannot find an answer
- Works with **Groq** (default) or **Google Gemini**, and falls back to showing matching passages if the AI is unreachable

**Security**
- **Role-based access** (standard user, admin) plus **department-only documents** (HR, Finance, Engineering by default)
- The access filter runs in the database query **before** any text is decrypted
- Uploaded files **and** every searchable passage are **encrypted** (Fernet)
- Passwords hashed with **bcrypt**; signed **JWT** login tokens that expire after 30 minutes and stop working after a password reset
- **Login lockout** after 5 failed attempts
- **Blocked-attempt alerts**: when someone asks about content they cannot see, they get a normal "not found" reply (the system never reveals that a hidden file exists), and admins are alerted
- **Sensitive-data scanner** on upload: flags passwords, salary figures, national ID numbers and card numbers, and locks such files to admins automatically
- **Audit log** of logins, uploads, questions and admin actions, with **CSV export**
- New accounts are always standard users; the first admin comes from your `.env` file

**Admin tools**
- System status, blocked attempts, and the audit log in one tab
- Assign departments, change roles, disable or delete users, reset passwords
- Change who can read any document, or delete it (its searchable text is removed too)

## How it works

1. **Upload:** the file is checked (type, size), its text is extracted and scanned for sensitive content, then the original is encrypted and stored under a random name. The text is split into passages, each passage is encrypted and tagged with its access level.
2. **Ask:** the server reads the user's role and department from the database, loads only the passages that user may read, ranks them (BM25 keyword scoring), and sends the best ones to the AI.
3. **Answer:** the AI writes an answer from those passages only. The reply includes the source file names. If the question matched hidden content, the user gets the same "not found" reply and the attempt is logged for admins.

## Tech stack

| Area | Tools |
|---|---|
| Backend | Python 3.10+, FastAPI, Uvicorn, Pydantic |
| Database | SQLite via SQLAlchemy |
| AI | Groq API (default model `openai/gpt-oss-120b`), Google Gemini (optional) |
| Search | Own BM25 implementation with light stemming and PDF spacing repair |
| Security | cryptography (Fernet), bcrypt, python-jose (JWT) |
| File reading | pypdf, python-docx |
| Frontend | Plain HTML, CSS and JavaScript (no frameworks) |
| Testing | unittest, pytest, FastAPI TestClient |

## Quick start (Windows)

```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Open `.env` and fill in your admin login and AI key (see Configuration below), then:

```bash
uvicorn main:app --reload
```

Open **http://127.0.0.1:8000/portal** and log in with the admin account from your `.env`. (On macOS/Linux use `source venv/bin/activate` and `cp .env.example .env`.)

### Configuration (`.env`)

| Variable | Purpose |
|---|---|
| `ADMIN_USERNAME`, `ADMIN_PASSWORD` | First admin account, created on startup if it does not exist |
| `LLM_PROVIDER` | `groq`, `gemini` or `offline`. Leave empty to pick from the keys you set |
| `GROQ_API_KEY`, `GROQ_MODEL` | Get a key at console.groq.com/keys |
| `GOOGLE_API_KEY`, `GEMINI_MODEL` | Only if you use Gemini |
| `DEPARTMENTS` | Comma-separated list, default `HR,Finance,Engineering` |
| `LLM_TIMEOUT` | Seconds to wait for the AI (default 45) |

Without any AI key the app still runs in **offline mode** and shows the most relevant passages instead of a written answer. Run `python find_models.py` to list the models your key can use and `python check_ai.py` to diagnose key problems.

## Try the security demo

1. Log in as admin. Upload a file as **Admins only** (for example one containing a salary) and another as **Everyone**.
2. Create a second account and log in as that standard user.
3. Ask for the salary. The reply is "not found", with no hint that the file exists.
4. Ask about the public file. You get an answer with its source.
5. Back as admin, open the **Admin** tab to see the blocked attempt and the audit log.

## Tests

```bash
python test_core.py     # search engine, access rules, scanner (22 tests)
pytest -v               # full API tests (13 tests)
python demo_cli.py      # terminal demo of the salary scenario
```

## Project structure

```
main.py          app start, serves the portal
config.py        settings and secrets (reads .env)
models.py        database tables (users, documents, audit log)
auth.py          register, login, tokens, user management
document.py      upload, list, chat, access changes, audit routes
rag.py           file reading, search, access filter, AI calls, scanner
encryption.py    Fernet encryption helpers
index.html       the whole portal interface
reset_admin.py   emergency admin password reset
check_ai.py, find_models.py, inspect_doc.py   helper tools
test_core.py, test_app.py, conftest.py, demo_cli.py   tests and demo
```

## Security notes

- **Never commit `.env` or the `data/` folder.** They hold your API key, admin password, encryption keys, users and documents. The included `.gitignore` already excludes them.
- If an API key is ever exposed, revoke it and create a new one.
- The app serves plain HTTP. For anything beyond a local demo, put it behind HTTPS.
- Search is keyword-based, so it matches words, not meaning.

## Limitations and roadmap

- Meaning-based search with embeddings
- Email-based password reset and single sign-on
- Docker deployment and PostgreSQL for larger teams
- OCR for scanned PDFs
- Persistent login-attempt tracking (currently reset when the server restarts)


## Acknowledgements

Built during the **Cybersecurity Fundamentals Course** bootcamp at **Bano Qabil, Pakistan**. Thanks to our instructors and mentors.

## License

MIT. See `LICENSE`. `[Replace the name in LICENSE with yours]`
