"""Emergency admin password reset. Run from the vaultmind folder (the one containing main.py and data/).

    python reset_admin.py                      uses ADMIN_USERNAME / ADMIN_PASSWORD from your .env
    python reset_admin.py admin "NewPass123"   or give the username and new password directly

It sets the password, makes the account an active admin (creating it if missing), and signs out its old sessions.
"""
import sys

import bcrypt

import config
import models

user = sys.argv[1] if len(sys.argv) > 1 else config.ADMIN_USERNAME
pw = sys.argv[2] if len(sys.argv) > 2 else config.ADMIN_PASSWORD
if not user or not pw:
    raise SystemExit('Give a username and password:  python reset_admin.py admin "NewPass123"')
if not 8 <= len(pw) <= 72:
    raise SystemExit("Password must be 8-72 characters.")

models.init_db()
hashed = bcrypt.hashpw(pw.encode()[:72], bcrypt.gensalt()).decode()
with models.SessionLocal() as db:
    u = db.query(models.User).filter_by(username=user).first()
    if u:
        u.hashed_password, u.role, u.is_active = hashed, "admin", True
        action = "updated"
    else:
        db.add(models.User(username=user, hashed_password=hashed, role="admin"))
        action = "created"
    db.commit()
print(f"Admin '{user}' {action}. Database used: {config.DB_PATH.resolve()}")
print("You can log in now with that username and password.")
