import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


IDENTIDAD_FILE = Path("identidad.json")


def generar_identidad():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes_raw()
    public_bytes = public_key.public_bytes_raw()

    # did:key para una clave Ed25519 usa el multicodec 0xed01
    multicodec_public = b"\xed\x01" + public_bytes

    # Base58btc, prefijo "z"
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    numero = int.from_bytes(multicodec_public, "big")
    encoded = ""

    while numero:
        numero, resto = divmod(numero, 58)
        encoded = alphabet[resto] + encoded

    # Conservar ceros iniciales, aunque Ed25519 normalmente no los necesita
    ceros = 0
    for byte in multicodec_public:
        if byte == 0:
            ceros += 1
        else:
            break

    did = "did:key:" + ("1" * ceros) + "z" + encoded

    identidad = {
        "did": did,
        "public_key": base64.b64encode(public_bytes).decode("ascii"),
        "private_key": base64.b64encode(private_bytes).decode("ascii")
    }

    IDENTIDAD_FILE.write_text(
        json.dumps(identidad, indent=2),
        encoding="utf-8"
    )

    return did


if __name__ == "__main__":
    print("========================================")
    print(" TECHN0CORE - NUEVA IDENTIDAD")
    print("========================================")

    if IDENTIDAD_FILE.exists():
        print("\n[AVISO] Ya existe identidad.json.")
        print("No voy a sobrescribirla automáticamente.")

        identidad = json.loads(
            IDENTIDAD_FILE.read_text(encoding="utf-8")
        )

        print("\nDID existente:")
        print(identidad["did"])

    else:
        did = generar_identidad()

        print("\n[OK] Identidad creada")
        print("----------------------------------------")
        print("DID:", did)
        print("----------------------------------------")
        print("Guardada localmente en: identidad.json")

    print("\nIMPORTANTE:")
    print("NO publiques identidad.json en GitHub.")
    print("Contiene la clave privada.")
    print("========================================")