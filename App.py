# JWT ülesanne - 4. osa: mini-API
# Lihtne versioon (Flask + PyJWT)
#
# Server:     http://127.0.0.1:5000

import datetime
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

secret = "saladus123"

# Kasutajad - paroolid koodis, nagu ülesanne lubab
kasutajad = {
    "mari": {"parool": "parool123", "sub": "1024", "role": "student"},
    "admin": {"parool": "admin123", "sub": "1", "role": "admin"},
}


# POST/login - võtab kasutajanime ja parooli, tagastab tokeni
@app.route("/login", methods=["POST"])
def login():
    andmed = request.get_json()
    nimi = andmed["username"]
    parool = andmed["password"]

    # Kontrollime, kas kasutaja on olemas ja parool õige
    if nimi not in kasutajad or kasutajad[nimi]["parool"] != parool:
        return jsonify({"viga": "Vale kasutajanimi või parool"}), 401

    kasutaja = kasutajad[nimi]

    # Token aegub 5 minuti pärast
    aegub = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
    payload = {
        "sub": kasutaja["sub"],
        "role": kasutaja["role"],
        "exp": aegub,
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    return jsonify({"token": token})


# GET /profiil - ainult kehtiva tokeniga
@app.route("/profiil", methods=["GET"])
def profiil():
    auth = request.headers.get("Authorization")

    # Kas token üldse olemas?
    if auth is None or not auth.startswith("Bearer "):
        return jsonify({"viga": "Token puudub"}), 401

    token = auth.replace("Bearer ", "")

    # Proovime tokenit kontrollida
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return jsonify({"viga": "Token on aegunud"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"viga": "Token on vigane"}), 401

    return jsonify({"sub": payload["sub"], "role": payload["role"], "exp": payload["exp"]})


# GET /admin - ainult admin rolliga
@app.route("/admin", methods=["GET"])
def admin():
    auth = request.headers.get("Authorization")

    if auth is None or not auth.startswith("Bearer "):
        return jsonify({"viga": "Token puudub"}), 401

    token = auth.replace("Bearer ", "")

    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return jsonify({"viga": "Token on aegunud"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"viga": "Token on vigane"}), 401

    # Token kehtib, aga kas roll on admin?
    if payload["role"] != "admin":
        return jsonify({"viga": "Ligipääs keelatud, vaja on admin rolli"}), 403

    return jsonify({"sõnum": "Tere tulemast, admin!"})


if __name__ == "__main__":
    app.run(debug=True)