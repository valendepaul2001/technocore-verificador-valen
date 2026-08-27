import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization


DID = "did:key:z6MkgthTNPGR6iLhgemR2vC9CvQu6idLvuBYboKVcGgEbWBQ"
FINGERPRINT = "5844a5b370dba20a"

PRIVATE_KEY_FILE = Path(
    r"C:\Users\valen\flop-agent\private_key.pem"
)

PROOF_FILE = Path("proof.json")


def cargar_clave():
    if not PRIVATE_KEY_FILE.exists():
        raise FileNotFoundError(
            f"No se encontró la clave en: {PRIVATE_KEY_FILE}"
        )

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


if __name__ == "__main__":

    print("========================================")
    print(" TECHN0CORE - SIGNED PROOF GENERATOR")
    print("========================================")

    print("\nDID:")
    print(DID)

    print("\nFingerprint:")
    print(FINGERPRINT)

    try:
        private_key = cargar_clave()
    except Exception as error:
        print("\n[ERROR]", error)
        raise SystemExit(1)

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
    print("Hash:", proof["message_hash"])
    print("Firma generada: SI")
    print("----------------------------------------")
    print("[OK] Guardado en:", PROOF_FILE)
    print("========================================")