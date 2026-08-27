# Technocore DID Verifier & Signed Contribution Proof Generator

Herramienta local para verificar identidades DID y generar proofs
criptográficamente firmados para contribuciones en Technocore.

## Identity

- DID: did:key:z6MkgthTNPGR6iLhgemR2vC9CvQu6idLvuBYboKVcGgEbWBQ
- Fingerprint: 5844a5b370dba20a
- Key type: Ed25519

## Features

- Validación de DID did:key
- Generación de contribution proofs
- Firma criptográfica Ed25519
- Hash SHA-256
- Verificación independiente de proofs
- Detección de modificaciones
- Protección de archivos privados

## Usage

Para generar un proof:

python proof_generator.py

Para verificarlo:

python verificador.py

Si el proof es válido:

STATUS: VERIFIED

## Security

La clave privada nunca se publica en este repositorio.

Los archivos privados están excluidos mediante .gitignore.

## Contribution

Este proyecto proporciona una herramienta local para generar y verificar
proofs criptográficamente firmados asociados a una identidad DID.

## Disclaimer

Un proof generado localmente no implica por sí mismo reconocimiento oficial
por parte de Technocore.