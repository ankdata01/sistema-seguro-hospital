"""Generación, cifrado y carga de llaves RSA."""
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generar_par_rsa() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    privada = rsa.generate_private_key(public_exponent=65537, key_size=2048); return privada, privada.public_key()

def serializar_publica(publica: rsa.RSAPublicKey) -> str:
    return publica.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")

def guardar_privada_cifrada(privada: rsa.RSAPrivateKey, ruta: Path, contrasena: str) -> None:
    pem = privada.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.BestAvailableEncryption(contrasena.encode("utf-8")))
    ruta.write_bytes(pem)
    try: ruta.chmod(0o600)
    except OSError: pass

def cargar_privada(ruta: Path, contrasena: str) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(ruta.read_bytes(), password=contrasena.encode("utf-8"))

def cargar_publica_desde_pem(pem_str: str) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))

def guardar_publica(publica: rsa.RSAPublicKey, ruta: Path) -> None:
    ruta.write_text(serializar_publica(publica), encoding="utf-8")
