import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging

def generator_sym_key() -> bytes:
    """
    функция для генерации ключа
    :return: ключ симметричного алгоритма шифрования
    """
    key = os.urandom(16)

    return key


def encrypt_sym(key: bytes, text: bytes) -> bytes:
    """
    Функция для шифровать текст алгоримтом симметричгного SM4
    :param key: Текст
    :param text: ключ
    :return: зашифрованный текст
    """
    padder = padding.ANSIX923(128).padder()
    padded_text = padder.update(text) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.SM4(key), modes.CBC(iv))

    encryptor = cipher.encryptor()
    c_text = encryptor.update(padded_text) + encryptor.finalize()
    return iv + c_text


def decrypt_sym(key: bytes, cipher_text: bytes):
    """
    Функция для расшифровать текст
    :param key: ключ
    :param cipher_text: зашифрованный текст
    :return: расшифрованный текст
    """
    cipher_text, iv = cipher_text[16:], cipher_text[:16]
    cipher = Cipher(algorithms.SM4(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    dc_text = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = padding.ANSIX923(128).unpadder()
    unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()
    return unpadded_dc_text
