import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


PROOF_FILE = Path("proof.json")

EXPECTED_DID = (
    "did:key:z6MkgthTNPGR6iLhgemR2vC9CvQu6idLvuBYboKVcGgEbWBQ"
)

EXPECTED_FINGERPRINT = "5844a5b370dba20a"


def base58_decode(text):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    numero = 0

    for caracter in text:
        if caracter not in alphabet:
            raise ValueError("DID contiene un carácter Base58 inválido")

        numero = numero * 58 + alphabet.index(caracter)

    resultado = numero.to_bytes(
        (numero.bit_length() + 7) // 8,
        "big"
    )

    ceros = 0

    for caracter in text:
        if caracter == "1":
            ceros += 1
        else:
            break

    return b"\x00" * ceros + resultado


def obtener_clave_publica_desde_did(did):
    if not did.startswith("did:key:z"):
        raise ValueError("No es un did:key Base58btc válido")

    encoded = did[len("did:key:z"):]

    multicodec = base58_decode(encoded)

    if not multicodec.startswith(b"\xed\x01"):
        raise ValueError(
            "El DID no contiene una clave pública Ed25519"
        )

    public_key_bytes = multicodec[2:]

    if len(public_key_bytes) != 32:
        raise ValueError(
            "La clave pública Ed25519 debe tener 32 bytes"
        )

    return public_key_bytes


def cargar_proof():
    if not PROOF_FILE.exists():
        raise FileNotFoundError("No existe proof.json")

    with open(PROOF_FILE, "r", encoding="utf-8") as archivo:
        return json.load(archivo)


def verificar_proof(proof):

    required = [
        "type",
        "did",
        "fingerprint",
        "repository",
        "commit",
        "contribution",
        "timestamp",
        "message_hash",
        "signature"
    ]

    for campo in required:
        if campo not in proof:
            return False, f"Falta el campo: {campo}"

    if proof["type"] != "TechnocoreContributionProof":
        return False, "Tipo de proof incorrecto"

    if proof["did"] != EXPECTED_DID:
        return False, "El DID no coincide"

    if proof["fingerprint"] != EXPECTED_FINGERPRINT:
        return False, "El fingerprint no coincide"

    datos = {
        "type": proof["type"],
        "did": proof["did"],
        "fingerprint": proof["fingerprint"],
        "repository": proof["repository"],
        "commit": proof["commit"],
        "contribution": proof["contribution"],
        "timestamp": proof["timestamp"]
    }

    mensaje = json.dumps(
        datos,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":")
    ).encode("utf-8")

    hash_calculado = hashlib.sha256(mensaje).hexdigest()

    if hash_calculado != proof["message_hash"]:
        return False, "El hash del mensaje no coincide"

    try:
        firma = base64.urlsafe_b64decode(
            proof["signature"] + "=="
        )
    except Exception:
        return False, "Firma Base64 inválida"

    try:
        public_key_bytes = obtener_clave_publica_desde_did(
            proof["did"]
        )

        public_key = Ed25519PublicKey.from_public_bytes(
            public_key_bytes
        )

        public_key.verify(
            firma,
            mensaje
        )

    except Exception:
        return False, "Firma Ed25519 inválida"

    return True, "Proof criptográficamente válido"


if __name__ == "__main__":

    print("========================================")
    print(" TECHN0CORE - PROOF VERIFIER")
    print("========================================")

    try:
        proof = cargar_proof()

        print("\nDID:")
        print(proof.get("did", "N/A"))

        print("\nFingerprint:")
        print(proof.get("fingerprint", "N/A"))

        print("\nRepository:")
        print(proof.get("repository", "N/A"))

        print("\nCommit:")
        print(proof.get("commit", "N/A"))

        print("\nContribución:")
        print(proof.get("contribution", "N/A"))

        valido, mensaje = verificar_proof(proof)

        print("\n----------------------------------------")

        if valido:
            print("[OK]", mensaje)
            print("[OK] DID coincide")
            print("[OK] Fingerprint coincide")
            print("[OK] Repository presente")
            print("[OK] Commit presente")
            print("[OK] Hash coincide")
            print("[OK] Firma Ed25519 válida")
            print("\nSTATUS: VERIFIED")
        else:
            print("[ERROR]", mensaje)
            print("\nSTATUS: INVALID")

        print("----------------------------------------")
        print("========================================")

    except Exception as error:
        print("\n[ERROR]", error)
        print("\nSTATUS: INVALID")
        print("========================================")