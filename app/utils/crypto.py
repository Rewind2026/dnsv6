"""
加密工具模块 - 用于加密存储敏感信息
"""
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def get_or_create_key() -> bytes:
    """获取或创建加密密钥"""
    key_file = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "data",
        ".secret_key"
    )
    
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        # 生成新密钥
        key = Fernet.generate_key()
        os.makedirs(os.path.dirname(key_file), exist_ok=True)
        with open(key_file, 'wb') as f:
            f.write(key)
        return key


def get_cipher() -> Fernet:
    """获取加密器实例"""
    key = get_or_create_key()
    return Fernet(key)


def encrypt_text(text: str) -> str:
    """加密文本"""
    if not text:
        return ""
    try:
        cipher = get_cipher()
        encrypted = cipher.encrypt(text.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    except Exception:
        return text


def decrypt_text(encrypted_text: str) -> str:
    """解密文本"""
    if not encrypted_text:
        return ""
    try:
        cipher = get_cipher()
        encrypted = base64.urlsafe_b64decode(encrypted_text.encode())
        decrypted = cipher.decrypt(encrypted)
        return decrypted.decode()
    except Exception:
        # 如果解密失败，可能是明文存储的旧数据，直接返回
        return encrypted_text
