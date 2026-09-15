import os
import re
import time
import secrets
import hashlib
import base64

from flask import Flask, request, jsonify, session, render_template

app = Flask(__name__)

# 强制 SECRET_KEY 
_secret = os.environ.get("SECRET_KEY")
if not _secret or _secret in ("dev_secret_change_me", "change_me_in_prod"):
    raise RuntimeError("SECRET_KEY must be set to a random value")
app.secret_key = _secret

FLAG = os.environ.get("FLAG", "flag{orbital_gate_demo_flag}")

P_SALT = "ORBITAL_GATE_V2"
F_SALT = "FINAL_DOCK_7"
T_SALT = "TICKET_PARSE_V2"
ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

users = {}
nonces = {}


def fnv1a(s: str) -> int:
    h = 0x811c9dc5
    for b in s.encode("utf-8"):
        h ^= b
        h = (h * 0x01000193) & 0xffffffff
    return h


def rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xffffffff


def to_base32_like(data: bytes) -> str:
    bits = 0
    value = 0
    out = []
    for b in data:
        value = (value << 8) | b
        bits += 8
        while bits >= 5:
            out.append(ALPHA[(value >> (bits - 5)) & 31])
            bits -= 5
            value &= (1 << bits) - 1 if bits else 0
    if bits > 0:
        out.append(ALPHA[(value << (5 - bits)) & 31])
    return "".join(out)


def transform_portal_bytes(raw: str, key: int) -> bytes:
    data = raw.encode("utf-8")
    out = bytearray()
    for i, b in enumerate(data):
        k = (key >> ((i % 4) * 8)) & 0xff
        x = b ^ k
        x = ((x << 3) | (x >> 5)) & 0xff
        out.append(x)
    return bytes(out)


def expected_portal_token(username: str, uid: int, ts: int) -> str:
    raw = f"{username}|{uid}|{ts}|{P_SALT}"
    key = ((uid * 2654435761) ^ 0x9e3779b9) & 0xffffffff
    encoded = to_base32_like(transform_portal_bytes(raw, key))
    checksum = f"{fnv1a(raw) & 0xffffffff:08x}"[-4:]
    return f"v1.{ts}.{encoded}.{checksum}"


def verify_portal_token(token: str, username: str, uid: int) -> bool:
    parts = token.split(".")
    if len(parts) != 4 or parts[0] != "v1":
        return False
    try:
        ts = int(parts[1])
    except ValueError:
        return False
    if abs(time.time() - ts) > 180:
        return False
    expected = expected_portal_token(username, uid, ts)
    return secrets.compare_digest(token, expected)


def to_base36(n: int) -> str:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if n == 0:
        return "0"
    out = ""
    while n:
        n, r = divmod(n, 36)
        out = alphabet[r] + out
    return out


def make_ticket(uid: int) -> str:
    uid_part = to_base36(uid).upper()
    rand_part = secrets.token_hex(8).upper()
    seed = f"{uid_part}:{rand_part}:{T_SALT}"
    check_part = f"{fnv1a(seed) & 0xffff:04X}"
    return f"ORB-{uid_part}-{rand_part}-{check_part}"


def parse_ticket(ticket: str):
    m = re.fullmatch(r"ORB-([0-9A-Z]+)-([0-9A-F]{16})-([0-9A-F]{4})", ticket)
    if not m:
        raise ValueError("bad ticket")
    return {
        "raw": ticket,
        "uidPart": m.group(1),
        "randomPart": m.group(2),
        "checkPart": m.group(3),
    }


def verify_ticket_integrity(ticket: str, uid: int) -> bool:
    try:
        parts = parse_ticket(ticket)
    except ValueError:
        return False
    if parts["uidPart"] != to_base36(uid).upper():
        return False
    seed = f"{parts['uidPart']}:{parts['randomPart']}:{T_SALT}"
    expected_check = f"{fnv1a(seed) & 0xffff:04X}"
    return secrets.compare_digest(parts["checkPart"], expected_check)


def xor_with_salt(text: str, salt: str) -> bytes:
    t = text.encode("utf-8")
    s = salt.encode("utf-8")
    return bytes([b ^ s[i % len(s)] for i, b in enumerate(t)])


def derive_session_proof(uid, ticket, nonce, client_nonce):
    seed = f"{uid}:{ticket}:{nonce}:{client_nonce}:{P_SALT}"
    h1 = fnv1a(seed)
    h2 = fnv1a(seed[::-1])
    proof = rotl32(h1 ^ h2, 7)
    return f"{proof:08x}"


def sign_final_server(uid, ticket, nonce, client_nonce):
    parts = parse_ticket(ticket)
    proof = derive_session_proof(uid, ticket, nonce, client_nonce)
    proof_int = int(proof, 16)

    seed = f"{uid}:{ticket}:{nonce}:{client_nonce}:{F_SALT}"
    h1 = fnv1a(seed)
    h2 = fnv1a(seed[::-1])
    h = (h1 ^ rotl32(h2, 13) ^ proof_int) & 0xffffffff

    a = nonce[:8]
    b = parts["uidPart"]
    c = parts["checkPart"]
    d = f"{h:08x}"
    e = proof[:4]
    payload = f"{a}.{b}.{c}.{d}.{e}"

    xored = xor_with_salt(payload, F_SALT)
    b64 = base64.urlsafe_b64encode(xored).decode().rstrip("=")
    checksum = f"{fnv1a(payload + ticket + F_SALT) & 0xffff:04x}"
    return f"v2.{b64}.{checksum}"


def current_user_or_none():
    username = session.get("username")
    uid = session.get("uid")
    if not username or not uid:
        return None
    user = users.get(username)
    if not user or user["uid"] != uid:
        return None
    return user


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not re.fullmatch(r"[A-Za-z0-9_]{3,16}", username):
        return jsonify(error="invalid username"), 400
    if len(password) < 6:
        return jsonify(error="weak password"), 400
    if username in users:
        return jsonify(error="exists"), 409

    uid = 1000 + len(users) + 1
    users[username] = {
        "uid": uid,
        "password_hash": hashlib.sha256(password.encode()).hexdigest(),
        "dept": "Public Relations",
    }
    session["uid"] = uid
    session["username"] = username
    return jsonify(
        ok=True, uid=uid, username=username, dept=users[username]["dept"]
    )


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    user = users.get(username)
    if not user:
        return jsonify(error="bad credentials"), 401
    if not secrets.compare_digest(
        hashlib.sha256(password.encode()).hexdigest(), user["password_hash"]
    ):
        return jsonify(error="bad credentials"), 401
    session["uid"] = user["uid"]
    session["username"] = username
    return jsonify(
        ok=True, uid=user["uid"], username=username, dept=user["dept"]
    )


@app.get("/api/me")
def me():
    user = current_user_or_none()
    if not user:
        return jsonify(error="unauthorized"), 401
    return jsonify(
        ok=True,
        uid=user["uid"],
        username=session["username"],
        dept=user["dept"],
    )


@app.post("/api/internal/bootstrap")
def internal_bootstrap():
    user = current_user_or_none()
    if not user:
        return jsonify(error="unauthorized"), 401

    username = session["username"]
    uid = user["uid"]
    token = request.headers.get("X-Portal-Token", "")

    if not verify_portal_token(token, username, uid):
        return jsonify(error="unauthorized"), 401

    nonce = secrets.token_hex(16)
    ticket = make_ticket(uid)

    nonces[nonce] = {
        "uid": uid,
        "ticket": ticket,
        "created": time.time(),
        "used": False,
    }

    return jsonify(
        ok=True,
        nonce=nonce,
        ticket=ticket,
        next="/api/internal/final",
        expires_in=180,
    )


@app.post("/api/internal/final")
def internal_final():
    user = current_user_or_none()
    if not user:
        return jsonify(error="unauthorized"), 401

    data = request.get_json(silent=True) or {}
    nonce = data.get("nonce") or ""
    client_nonce = (data.get("client_nonce") or "").lower()
    signature = data.get("signature") or ""

    bad = (
        jsonify(status="invalid_badge", message="Badge verification failed"),
        403,
    )

    rec = nonces.get(nonce)
    if not rec or rec["used"]:
        return bad
    if rec["uid"] != user["uid"]:
        return bad
    if time.time() - rec["created"] > 180:
        return bad
    if not re.fullmatch(r"[0-9a-f]{16}", client_nonce):
        return bad
    if not verify_ticket_integrity(rec["ticket"], rec["uid"]):
        return bad

    expected = sign_final_server(
        rec["uid"], rec["ticket"], nonce, client_nonce
    )
    if not secrets.compare_digest(signature, expected):
        return bad

    rec["used"] = True
    return jsonify(ok=True, flag=FLAG)


@app.post("/api/admin/flag")
def fake_admin_flag():
    return jsonify(error="forbidden"), 403


@app.post("/api/debug/verify")
def fake_debug_verify():
    return jsonify(valid=False, reason="debug disabled"), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)