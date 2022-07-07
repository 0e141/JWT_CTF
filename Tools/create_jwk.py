import json
from jwcrypto import jwk

with open("keypair.pem", "rb") as pem_file:
        keypair = jwk.JWK.from_pem(pem_file.read())

pub_key = keypair.export(private_key=False)

jwks = {}
jwks["keys"] = [json.loads(pub_key)]
jwks["keys"][0]["use"] = "sig"
jwks["keys"][0]["alg"] = "RS256"

with open("jwks.json", "w") as out:
        out.write(json.dumps(jwks))