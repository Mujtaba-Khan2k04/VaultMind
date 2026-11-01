from cryptography.fernet import Fernet
import config

_cipher = Fernet(config.VAULT_KEY.encode())


def encrypt_bytes(data: bytes) -> bytes:
    return _cipher.encrypt(data)


def decrypt_bytes(data: bytes) -> bytes:
    return _cipher.decrypt(data)


def encrypt_text(text: str) -> bytes:
    return _cipher.encrypt(text.encode("utf-8"))


def decrypt_text(blob: bytes) -> str:
    return _cipher.decrypt(blob).decode("utf-8")
