from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def generation_asym_key():
    """
    Функция генерирует ключи для асимметричного шифрования
    :return: закрытый ключ и открытый ключ
    """
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()
    return private_key, public_key


def encrypt_asym(public_key, text: bytes):
    """
    Функция производит асимметричное шифрование по открытому ключу
    :param public_key: открытый ключ
    :param text: текст, который шифруем
    :return:
    """
    c_text = public_key.encrypt(text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                   algorithm=hashes.SHA256(), label=None))
    return c_text


def decrypt_asym(private_key, text: bytes):
    """
    ункция расшифровывает асимметрично зашифрованный текст, с помощью закрытого ключа
    :param private_key: закрытый ключ
    :param text: зашифрованный текст
    :return:
    """
    dc_text = private_key.decrypt(text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                     algorithm=hashes.SHA256(), label=None))
    return dc_text
