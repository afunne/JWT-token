import base64
import hashlib
import hmac
import json
from datetime import datetime
from zoneinfo import ZoneInfo

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDI0IiwibmFtZSI6Ik1hcmkgTWFhc2lrYXMiLCJyb2xlIjoic3R1ZGVudCIsImlhdCI6MTc2MTIwNjQwMCwiZXhwIjoxNzYxMjEwMDAwfQ.ZL6DsKKTa2hRmEkkMASGBI7hZW8ot5bJS2I8oOxVTwM"


def b64url_decode(tekst):
    tekst += "=" * (-len(tekst) % 4)  # lisa puuduvad = märgid
    return base64.urlsafe_b64decode(tekst)


def b64url_encode(baidid):
    return base64.urlsafe_b64encode(baidid).rstrip(b"=").decode()


# Samm 2: dekodeeri päis ja payload (1. osa)
pais_b64, payload_b64, allkiri_b64 = token.split(".")
pais = json.loads(b64url_decode(pais_b64))
payload = json.loads(b64url_decode(payload_b64))
print("Päis:", pais)
print("Payload:", payload)
tz = ZoneInfo("Europe/Tallinn")
print("Väljastatud:", datetime.fromtimestamp(payload["iat"], tz))
print("Aegub:", datetime.fromtimestamp(payload["exp"], tz))
print("Kehtib praegu:", datetime.now(tz).timestamp() < payload["exp"])


# Samm 3: kontrolli allkirja (2. osa)
def allkirjasta(pais_b64, payload_b64, voti):
    sisend = f"{pais_b64}.{payload_b64}".encode()
    raasi = hmac.new(voti.encode(), sisend, hashlib.sha256).digest()
    return b64url_encode(raasi)


print("Õige võti:", hmac.compare_digest(allkirjasta(pais_b64, payload_b64, "saladus123"), allkiri_b64))
print("Vale võti:", hmac.compare_digest(allkirjasta(pais_b64, payload_b64, "saladus124"), allkiri_b64))


# Samm 4: proovi võltsida (3. osa)
voltsitud = dict(payload, role="admin")
voltsitud_b64 = b64url_encode(json.dumps(voltsitud, separators=(",", ":")).encode())
voltsitud_token = f"{pais_b64}.{voltsitud_b64}.{allkiri_b64}"  # vana allkiri
print("Võltsing läbib kontrolli:", hmac.compare_digest(allkirjasta(pais_b64, voltsitud_b64, "saladus123"), allkiri_b64))