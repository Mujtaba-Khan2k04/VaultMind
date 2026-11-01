"""Full API tests (need: pip install -r requirements.txt). Run: pytest -v"""
import pytest
from fastapi.testclient import TestClient

import auth
import main


@pytest.fixture(scope="module")
def client():
    with TestClient(main.app) as c:
        yield c


def token(c, user, pw):
    r = c.post("/auth/login", data={"username": user, "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}


def test_register_forces_standard_role(client):
    r = client.post("/auth/register", json={"username": "ali", "password": "AliPass123", "role": "admin"})
    assert r.status_code == 201
    assert client.get("/auth/me", headers=token(client, "ali", "AliPass123")).json()["role"] == "standard"


def test_weak_password_rejected(client):
    assert client.post("/auth/register", json={"username": "bob", "password": "123"}).status_code == 422


def test_requires_login(client):
    assert client.get("/documents/").status_code == 401
    assert client.post("/documents/chat", json={"query": "hi"}).status_code == 401


def test_full_role_based_flow(client):
    admin, user = token(client, "boss", "BossPass123"), token(client, "ali", "AliPass123")
    # normal user cannot upload confidential files
    f = {"file": ("salaries.txt", b"Ali earns 250000 PKR per month.", "text/plain")}
    assert client.post("/documents/upload", files=f, data={"access_level": "admin"}, headers=user).status_code == 403
    # admin uploads confidential + public docs
    r = client.post("/documents/upload", files=f, data={"access_level": "admin"}, headers=admin)
    assert r.status_code == 201
    salary_id = r.json()["id"]
    pub = {"file": ("leave.txt", b"Employees get 20 days of annual leave.", "text/plain")}
    assert client.post("/documents/upload", files=pub, data={"access_level": "standard"}, headers=user).status_code == 201
    # visibility
    assert {d["filename"] for d in client.get("/documents/", headers=user).json()} == {"leave.txt"}
    assert {d["filename"] for d in client.get("/documents/", headers=admin).json()} == {"salaries.txt", "leave.txt"}
    # THE key requirement: normal user cannot extract the salary
    q = {"query": "What is Ali's salary?"}
    assert "250000" not in client.post("/documents/chat", json=q, headers=user).json()["answer"]
    assert "250000" in client.post("/documents/chat", json=q, headers=admin).json()["answer"]
    # only admins delete / read audit / manage users
    assert client.delete(f"/documents/{salary_id}", headers=user).status_code == 403
    assert client.get("/documents/audit", headers=user).status_code == 403
    assert client.get("/auth/users", headers=user).status_code == 403
    assert client.delete(f"/documents/{salary_id}", headers=admin).status_code == 200
    assert "250000" not in client.post("/documents/chat", json=q, headers=admin).json()["answer"]
    actions = {a["action"] for a in client.get("/documents/audit", headers=admin).json()}
    assert {"upload", "chat", "delete", "login"} <= actions


def test_promote_user(client):
    admin = token(client, "boss", "BossPass123")
    assert client.put("/auth/users/ali/role", json={"role": "admin"}, headers=admin).status_code == 200
    assert client.get("/auth/me", headers=token(client, "ali", "AliPass123")).json()["role"] == "admin"
    assert client.put("/auth/users/boss/role", json={"role": "standard"}, headers=admin).status_code == 400


def test_bad_upload_type_rejected(client):
    admin = token(client, "boss", "BossPass123")
    r = client.post("/documents/upload", files={"file": ("x.exe", b"MZ", "application/octet-stream")}, headers=admin)
    assert r.status_code == 400


def test_login_rate_limit(client):
    auth._failures.clear()
    client.post("/auth/register", json={"username": "victim", "password": "VictimPass1"})
    for _ in range(5):
        assert client.post("/auth/login", data={"username": "victim", "password": "wrong"}).status_code == 401
    assert client.post("/auth/login", data={"username": "victim", "password": "VictimPass1"}).status_code == 429
    auth._failures.clear()


def test_sensitive_upload_guard(client):
    admin = token(client, "boss", "BossPass123")
    client.post("/auth/register", json={"username": "sam", "password": "SamPass1234"})
    sam = token(client, "sam", "SamPass1234")
    pw = {"file": ("pw.txt", b"The server password is: Delta-77X", "text/plain")}
    # admin uploading sensitive content as 'everyone' must confirm
    r = client.post("/documents/upload", files=pw, data={"access_level": "standard"}, headers=admin)
    assert r.status_code == 409 and r.json()["sensitive"]
    pw = {"file": ("pw.txt", b"The server password is: Delta-77X", "text/plain")}
    r = client.post("/documents/upload", files=pw, data={"access_level": "standard", "confirm_sensitive": "true"}, headers=admin)
    assert r.status_code == 201
    # a standard user's sensitive upload is locked to admins automatically
    pw2 = {"file": ("pw2.txt", b"Backup api key: ZX-991-QQ", "text/plain")}
    r = client.post("/documents/upload", files=pw2, data={"access_level": "standard"}, headers=sam)
    assert r.status_code == 201 and r.json()["auto_protected"] and r.json()["access_level"] == "admin"
    assert "pw2.txt" not in {d["filename"] for d in client.get("/documents/", headers=sam).json()}


def test_blocked_attempt_alert(client):
    admin = token(client, "boss", "BossPass123")
    sam = token(client, "sam", "SamPass1234")
    f = {"file": ("budget.txt", b"Quarterly budget for the finance department is 900000.", "text/plain")}
    assert client.post("/documents/upload", files=f, data={"access_level": "admin"}, headers=admin).status_code == 201
    r = client.post("/documents/chat", json={"query": "What is the finance department budget?"}, headers=sam)
    assert "900000" not in r.json()["answer"]
    assert "blocked" not in r.json()                      # never reveal the flag to the asker
    alerts = client.get("/documents/audit?action=access_denied", headers=admin).json()
    assert any(a["user"] == "sam" for a in alerts)


def test_scoped_chat(client):
    admin = token(client, "boss", "BossPass123")
    f = {"file": ("parking.txt", b"Parking permits are renewed every March.", "text/plain")}
    doc_id = client.post("/documents/upload", files=f, data={"access_level": "standard"}, headers=admin).json()["id"]
    r = client.post("/documents/chat", json={"query": "When are parking permits renewed?", "doc_id": doc_id}, headers=admin).json()
    assert r["sources"] == ["parking.txt"] and "March" in r["answer"]
    other = client.post("/documents/chat", json={"query": "annual leave", "doc_id": doc_id}, headers=admin).json()
    assert other["sources"] == []


def test_admin_controls(client):
    admin = token(client, "boss", "BossPass123")
    client.post("/auth/register", json={"username": "lee", "password": "LeePass1234"})
    # disable / enable a user
    assert client.put("/auth/users/lee/active", json={"active": False}, headers=admin).status_code == 200
    assert client.post("/auth/login", data={"username": "lee", "password": "LeePass1234"}).status_code == 401
    assert client.put("/auth/users/boss/active", json={"active": False}, headers=admin).status_code == 400
    assert client.put("/auth/users/lee/active", json={"active": True}, headers=admin).status_code == 200
    lee = token(client, "lee", "LeePass1234")
    assert client.put("/auth/users/boss/active", json={"active": False}, headers=lee).status_code == 403
    # change a document's access level
    f = {"file": ("memo.txt", b"The team picnic is on Friday.", "text/plain")}
    did = client.post("/documents/upload", files=f, data={"access_level": "standard"}, headers=admin).json()["id"]
    q = {"query": "When is the team picnic?"}
    assert "Friday" in client.post("/documents/chat", json=q, headers=lee).json()["answer"]
    assert client.put(f"/documents/{did}/access", json={"access_level": "admin"}, headers=admin).status_code == 200
    assert "Friday" not in client.post("/documents/chat", json=q, headers=lee).json()["answer"]
    assert client.put(f"/documents/{did}/access", json={"access_level": "standard"}, headers=lee).status_code == 403
    st = client.get("/documents/status", headers=admin).json()
    assert st["ai_mode"] == "Offline" and st["users"] >= 3
    assert client.get("/documents/status", headers=lee).status_code == 403


def test_departments_and_user_management(client):
    admin = token(client, "boss", "BossPass123")
    lee, sam = token(client, "lee", "LeePass1234"), token(client, "sam", "SamPass1234")
    # departments
    assert client.put("/auth/users/lee/department", json={"department": "Nonsense"}, headers=admin).status_code == 400
    assert client.put("/auth/users/lee/department", json={"department": "Finance"}, headers=lee).status_code == 403
    assert client.put("/auth/users/lee/department", json={"department": "Finance"}, headers=admin).status_code == 200
    f = {"file": ("fin.txt", b"The travel budget cap is 3000 dollars.", "text/plain")}
    assert client.post("/documents/upload", files=f, data={"access_level": "dept:Finance"}, headers=admin).status_code == 201
    q = {"query": "What is the travel budget cap?"}
    assert "3000" in client.post("/documents/chat", json=q, headers=lee).json()["answer"]
    assert "3000" not in client.post("/documents/chat", json=q, headers=sam).json()["answer"]
    assert "fin.txt" in {d["filename"] for d in client.get("/documents/", headers=lee).json()}
    assert "fin.txt" not in {d["filename"] for d in client.get("/documents/", headers=sam).json()}
    f2 = {"file": ("hrnote.txt", b"HR holiday list.", "text/plain")}
    assert client.post("/documents/upload", files=f2, data={"access_level": "dept:HR"}, headers=lee).status_code == 403
    f3 = {"file": ("finnote.txt", b"Finance holiday list.", "text/plain")}
    assert client.post("/documents/upload", files=f3, data={"access_level": "dept:Finance"}, headers=lee).status_code == 201
    # password reset logs the user out and sets the new password
    assert client.put("/auth/users/sam/password", json={"password": "short"}, headers=admin).status_code == 422
    assert client.put("/auth/users/sam/password", json={"password": "BrandNewPass9"}, headers=lee).status_code == 403
    assert client.put("/auth/users/sam/password", json={"password": "BrandNewPass9"}, headers=admin).status_code == 200
    assert client.get("/auth/me", headers=sam).status_code == 401                      # old token dead
    assert client.post("/auth/login", data={"username": "sam", "password": "SamPass1234"}).status_code == 401
    assert client.get("/auth/me", headers=token(client, "sam", "BrandNewPass9")).status_code == 200
    # delete user
    assert client.delete("/auth/users/boss", headers=admin).status_code == 400
    assert client.delete("/auth/users/sam", headers=lee).status_code == 403
    assert client.delete("/auth/users/sam", headers=admin).status_code == 200
    assert client.post("/auth/login", data={"username": "sam", "password": "BrandNewPass9"}).status_code == 401
    assert client.delete("/auth/users/ghost", headers=admin).status_code == 404


def test_audit_csv_export(client):
    admin = token(client, "boss", "BossPass123")
    lee = token(client, "lee", "LeePass1234")
    assert client.get("/documents/audit/export", headers=lee).status_code == 403
    r = client.get("/documents/audit/export", headers=admin)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert r.text.splitlines()[0] == "time_utc,user,action,detail" and "login" in r.text
