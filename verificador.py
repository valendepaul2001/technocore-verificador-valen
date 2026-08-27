import hashlib
import re


def validar_did(did):
    """Comprueba que el DID tenga formato did:key."""
    if not did:
        return False, "DID vacío"

    patron = r"^did:key:z[1-9A-HJ-NP-Za-km-z]+$"

    if re.match(patron, did):
        return True, "Formato DID válido"

    return False, "Formato DID inválido"


def fingerprint_did(did):
    """Genera un fingerprint reproducible del DID."""
    digest = hashlib.sha256(did.encode("utf-8")).hexdigest()
    return digest[:16]


def verificar_perfil(did, nombre="Technocore Agent"):
    """Verificación básica local del perfil."""
    valido, mensaje = validar_did(did)

    if not valido:
        return {
            "ok": False,
            "mensaje": mensaje
        }

    return {
        "ok": True,
        "mensaje": "Perfil básico válido",
        "did": did,
        "nombre": nombre,
        "fingerprint": fingerprint_did(did)
    }


if __name__ == "__main__":
    print("========================================")
    print(" TECHN0CORE - VERIFICADOR")
    print("========================================")

    did = input("\nPegá tu DID: ").strip()

    resultado = verificar_perfil(did)

    print()

    if resultado["ok"]:
        print("[OK]", resultado["mensaje"])
        print("DID:", resultado["did"])
        print("Nombre:", resultado["nombre"])
        print("Fingerprint:", resultado["fingerprint"])
    else:
        print("[ERROR]", resultado["mensaje"])

    print("\n========================================")