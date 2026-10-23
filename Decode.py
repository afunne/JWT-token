# JWT ülesanne - 1., 2. ja 3. osa

import base64
import json
import hmac
import hashlib
from datetime import datetime
from zoneinfo import ZoneInfo

# Ülesandes antud token ja salavõti
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDI0IiwibmFtZSI6Ik1hcmkgTWFhc2lrYXMiLCJyb2xlIjoic3R1ZGVudCIsImlhdCI6MTc2MTIwNjQwMCwiZXhwIjoxNzYxMjEwMDAwfQ.ZL6DsKKTa2hRmEkkMASGBI7hZW8ot5bJS2I8oOxVTwM"
secret = "saladus123"


# 1. OSA: dekodeerimine
print("1. OSA: DEKODEERIMINE")

# Jagame tokeni kolmeks osaks punktide kohalt
header_osa, payload_osa, allkiri = token.split(".")

# Base64URL vajab pikkust, mis jagub 4-ga. Lisame puuduvad "=" märgid.
header_tekst = base64.urlsafe_b64decode(header_osa + "==")
payload_tekst = base64.urlsafe_b64decode(payload_osa + "==")

# Teeme JSON-tekstist Pythoni sõnastiku
header = json.loads(header_tekst)
payload = json.loads(payload_tekst)

print("Päis:", header)
print("Payload:", payload)

# Unix-aja teisendamine Tallinna kuupäevaks
tallinn = ZoneInfo("Europe/Tallinn")
valjastatud = datetime.fromtimestamp(payload["iat"], tallinn)
aegub = datetime.fromtimestamp(payload["exp"], tallinn)
kehtivus_minutites = (payload["exp"] - payload["iat"]) / 60

# Kas token kehtib praegu? Võrdleme praegust aega.
praegu = datetime.now(tallinn).timestamp()
kehtib = payload["iat"] <= praegu <= payload["exp"]

print("Algoritm:", header["alg"])
print("Nimi:", payload["name"])
print("ID (sub):", payload["sub"])
print("Roll:", payload["role"])
print("Väljastatud:", valjastatud)
print("Aegub:", aegub)
print("Kehtivus:", kehtivus_minutites, "minutit")
if kehtib:
    print("Kas kehtib praegu? JAH")
else:
    print("Kas kehtib praegu? EI, token on aegunud")


# 2. OSA: allkirja kontroll
print()
print("2. OSA: ALLKIRJA KONTROLL")

# Allkiri arvutatakse osadest "header.payload" salavõtmega
sonum = header_osa + "." + payload_osa

# HMAC-SHA256 õige võtmega
minu_allkiri_baidid = hmac.new(secret.encode(), sonum.encode(), hashlib.sha256).digest()
minu_allkiri = base64.urlsafe_b64encode(minu_allkiri_baidid).decode().replace("=", "")

print("Tokeni allkiri:", allkiri)
print("Minu allkiri:  ", minu_allkiri)
if minu_allkiri == allkiri:
    print("Klapib? JAH, token on ehtne")
else:
    print("Klapib? EI")

# Sama asi vale võtmega
vale_baidid = hmac.new("saladus124".encode(), sonum.encode(), hashlib.sha256).digest()
vale_allkiri = base64.urlsafe_b64encode(vale_baidid).decode().replace("=", "")
print("Vale võtmega:  ", vale_allkiri)
print("Klapib? EI, vale võti annab täiesti teise allkirja")


# 3. OSA: võltsimiskatse
print()
print("3. OSA: VÕLTSIMINE (role -> admin)")

# Muudame rolli payloadis
payload["role"] = "admin"

# Kodeerime uue payloadi tagasi Base64URL-i
uus_payload_tekst = json.dumps(payload).encode()
uus_payload_osa = base64.urlsafe_b64encode(uus_payload_tekst).decode().replace("=", "")

# Paneme kokku: uus payload + VANA allkiri
voltsitud_token = header_osa + "." + uus_payload_osa + "." + allkiri
print("Võltsitud token:", voltsitud_token)

# Arvutame, milline peaks olema õige allkiri uuele payloadile
uus_sonum = header_osa + "." + uus_payload_osa
oige_baidid = hmac.new(secret.encode(), uus_sonum.encode(), hashlib.sha256).digest()
oige_allkiri = base64.urlsafe_b64encode(oige_baidid).decode().replace("=", "")

print("Vana allkiri:", allkiri)
print("Õige allkiri uuele payloadile:", oige_allkiri)
print("Kontroll õnnestub? EI, allkiri ei vasta muudetud sisule")