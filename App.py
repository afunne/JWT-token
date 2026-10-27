# JWT mini-API
# Flask + PyJWT
#
# Lõpp-punktid:
#   POST /login    - kontrollib kasutajanime ja parooli, tagastab JWT
#   GET  /profiil  - ainult kehtiva tokeniga, tagastab tokeni andmed
#   GET  /admin    - ainult siis, kui tokenis on role = "admin"
 
import os
from datetime import datetime, timedelta, timezone
 
import jwt
from flask import Flask, request, jsonify
 
app = Flask(__name__)
 
# Salavõti loetakse keskkonnamuutujast, mitte ei ole koodis kirjas
SALAVOTI = os.environ.get("JWT_SALAVOTI")
if not SALAVOTI:
    raise SystemExit("Viga: keskkonnamuutuja JWT_SALAVOTI on määramata")
 
# Lubame ainult ühe algoritmi
ALGORITM = "HS256"
 
# Tokeni kehtivus: 5 minutit 10 testidele
# (aegunud tokeni testimiseks muuda ajutiselt: timedelta(seconds=10))
KEHTIVUS = timedelta(minutes=5)
 
# Testkasutajad (paroolid võivad olla nähtavad, need on ainult testimiseks)
KASUTAJAD = {
    "tudeng": {"parool": "tudeng123", "id": "1024", "role": "student"},
    "admin": {"parool": "admin123", "id": "1", "role": "admin"},
}
 
 
def loe_token():
    """Loeb tokeni päisest ja kontrollib seda.
    Tagastab (andmed, None) kui token on korras,
    või (None, veateade) kui midagi on valesti."""
    auth = request.headers.get("Authorization")
 
    # Token puudub
    if auth is None or not auth.startswith("Bearer "):
        return None, (jsonify({"viga": "Token puudub"}), 401)
 
    token = auth.replace("Bearer ", "")
 
    try:
        # decode kontrollib allkirja ja aegumist (exp)
        andmed = jwt.decode(token, SALAVOTI, algorithms=[ALGORITM])
    except jwt.ExpiredSignatureError:
        return None, (jsonify({"viga": "Token on aegunud"}), 401)
    except jwt.InvalidTokenError:
        return None, (jsonify({"viga": "Vigane token"}), 401)
 
    return andmed, None
 
 
@app.route("/login", methods=["POST"])
def login():
    andmed = request.get_json(silent=True) or {}
    nimi = andmed.get("kasutajanimi")
    parool = andmed.get("parool")
 
    kasutaja = KASUTAJAD.get(nimi)
    if kasutaja is None or kasutaja["parool"] != parool:
        return jsonify({"viga": "Vale kasutajanimi või parool"}), 401
 
    payload = {
        "sub": kasutaja["id"],
        "name": nimi,
        "role": kasutaja["role"],
        "exp": datetime.now(timezone.utc) + KEHTIVUS,
    }
    token = jwt.encode(payload, SALAVOTI, algorithm=ALGORITM)
    return jsonify({"token": token})
 
 
@app.route("/profiil", methods=["GET"])
def profiil():
    andmed, viga = loe_token()
    if viga:
        return viga
    return jsonify(andmed)
 
 
@app.route("/admin", methods=["GET"])
def admin():
    andmed, viga = loe_token()
    if viga:
        return viga
 
    # Token on kehtiv, aga kas kasutaja on admin?
    if andmed.get("role") != "admin":
        return jsonify({"viga": "Õigused puuduvad"}), 403
 
    return jsonify({"teade": "Tere, admin " + andmed["name"] + "!"})
 
 
if __name__ == "__main__":
    app.run(debug=True)