# Abiskript testjuhu "Muudetud (võltsitud) token" jaoks.
# Võtab kehtiva tokeni, muudab payloadis role väärtuseks "admin"
# ja jätab VANA allkirja alles.
#
# Kasutamine:  python voltsi.py <token>

import base64
import json
import sys

token = sys.argv[1]
pais, payload, allkiri = token.split(".")

# Dekodeerime payloadi (lisame puuduvad = märgid)
andmed = json.loads(base64.urlsafe_b64decode(payload + "=="))
andmed["role"] = "admin"

# Kodeerime muudetud payloadi tagasi
uus_payload = base64.urlsafe_b64encode(json.dumps(andmed).encode()).decode().replace("=", "")

# Uus payload + vana allkiri
print(pais + "." + uus_payload + "." + allkiri)