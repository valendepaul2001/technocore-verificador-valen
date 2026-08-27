import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


IDENTIDAD_FILE = Path("identidad.json")
PROOF_FILE = Path("proof.json")


def cargar_identidad():
    if not IDENTIDAD_FILE.exists():
        raise FileNotFoundError(
            "No existe identidad.json. Ejecutá primero identidad.py"
        )

    return json.loads(
        IDENTIDAD_FILE.read_text(encoding="utf-8")
    )


def generar_proof(identidad, contribucion):
    private_key_bytes = base64.b64decode(
        identidad["private_key"]
    )

    private_key = Ed25519PrivateKey.from_private_bytes(
        private_key_bytes
    )

    timestamp = datetime.now(timezone.utc).isoformat()

    datos = {
        "type": "TechnocoreContributionProof",
        "did": identidad["did"],
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

    proof = {
        **datos,
        "message_hash": hashlib.sha256(mensaje).hexdigest(),
        "signature": base64.b64encode(firma).decode("ascii")
    }

    return proof


if __name__ == "__main__":

    print("========================================")
    print(" TECHN0CORE - SIGNED PROOF GENERATOR")
    print("========================================")

    try:
        identidad = cargar_identidad()
    except Exception as error:
        print("\n[ERROR]", error)
        raise SystemExit(1)

    print("\nDID:")
    print(identidad["did"])

    contribucion = input(
        "\nDescribí tu contribución: "
    ).strip()

    if not contribucion:
        print("\n[ERROR] Falta describir la contribución.")
        raise SystemExit(1)

    proof = generar_proof(
        identidad,
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

    print("\n[OK] Proof firmado correctamente")
    print("----------------------------------------")
    print("Contribución:", proof["contribution"])
    print("Hash:", proof["message_hash"])
    print("Firma generada: SI")
    print("----------------------------------------")
    print("[OK] Guardado en:", PROOF_FILE)
    print("========================================")