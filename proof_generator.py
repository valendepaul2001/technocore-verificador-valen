import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization


DID = "did:key:z6MkgthTNPGR6iLhgemR2vC9CvQu6idLvuBYboKVcGgEbWBQ"
FINGERPRINT = "5844a5b370dba20a"

REPOSITORY = "https://github.com/valendepaul2001/technocore-verificador-valen"

COMMIT = "a1a0a700305a8620daa0972e7986d3ee442e3220"

PRIVATE_KEY_FILE = Path(
    r"C:\Users\valen\flop-agent\private_key.pem"
)

PROOF_FILE = Path("proof.json")


def cargar_clave():
    with open(PRIVATE_KEY_FILE, "rb") as archivo:
        return serialization.load_pem_private_key(
            archivo.read(),
            password=None
        )


def generar_proof(private_key, contribucion):

    timestamp = datetime.now(timezone.utc).isoformat()

    datos = {
        "type": "TechnocoreContributionProof",
        "did": DID,
        "fingerprint": FINGERPRINT,
        "repository": REPOSITORY,
        "commit": COMMIT,
        "contribution": contribucion,
        "timestamp": timestamp
    }

    mensaje = json.dumps(
        datos,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":")
    ).encode("utf-8")

    firma = private_key.sign(mensaje)

    return {
        **datos,
        "message_hash": hashlib.sha256(mensaje).hexdigest(),
        "signature": base64.urlsafe_b64encode(firma)
        .decode("utf-8")
        .rstrip("=")
    }


print("========================================")
print(" TECHN0CORE - SIGNED PROOF GENERATOR")
print("========================================")

print("\nDID:")
print(DID)

print("\nFingerprint:")
print(FINGERPRINT)

print("\nRepository:")
print(REPOSITORY)

print("\nCommit:")
print(COMMIT)

private_key = cargar_clave()

contribucion = input(
    "\nDescribí tu contribución: "
).strip()

if not contribucion:
    print("\n[ERROR] Falta describir la contribución.")
    raise SystemExit(1)

proof = generar_proof(
    private_key,
    contribucion
)

PROOF_FILE.write_text(
    json.dumps(
        proof,
        indent=2,
        ensure_ascii=False
    ),
    encoding="utf-8"
)

print("\n[OK] Proof firmado con tu clave Ed25519")
print("----------------------------------------")
print("DID:", proof["did"])
print("Fingerprint:", proof["fingerprint"])
print("Repository:", proof["repository"])
print("Commit:", proof["commit"])
print("Hash:", proof["message_hash"])
print("Firma generada: SI")
print("----------------------------------------")
print("[OK] Guardado en:", PROOF_FILE)
print("========================================")