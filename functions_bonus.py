from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import logging
import json


def load_settings(setting_file: str) -> dict:
    """
    Функция считывает файл настроек
    :param setting_file: название файла с настройками
    :return:настройки
    """
    settings = None
    try:
        with open(setting_file) as f:
            settings = json.load(f)
        logging.info('Усешно чтении настроек')
    except OSError as err:
        logging.warning(f' Ошибка при чтении настроек из файла {setting_file}\n{err}')
    return settings


def write_sym_key(key: bytes, filename: str) -> None:
    """
    Функция сохраняет ключ для симметричного шифрования
    :param key: ключ
    :param filename: название файла ключа
    :return: не возрашается
    """
    try:
        with open(filename, 'wb') as f:
            f.write(key)
        logging.info(f' Симметричный ключ записан в файла {filename}')
    except OSError as err:
        logging.warning(f' Ошибка при сохранении симметричного ключа в файл {filename}\n{err}')


def load_sym_key(filename: str) -> bytes:
    """
    Функция считывает ключ для симметричного шифрования из файла
    :param filename: азвание файла ключа
    :return: ключ
    """
    try:
        with open(filename, mode='rb') as f:
            content = f.read()
        logging.info(f' Симметричный ключ считан из файла {filename}')
    except OSError as err:
        logging.warning(f'Ошибка при чтении из файла{filename}\n{err}')
    return content


def write_asym_key(private_key, public_key, private_pem: str, public_pem: str) -> None:
    """
    Функция сохраняет закрытый и открытый ключ для ассиметричного шифрования
    :param private_key: закрытый ключ
    :param public_key: открытый ключ
    :param private_pem: название файла закрытого ключа
    :param public_pem: название файла открытого ключа
    :return: не возрашается
    """
    try:
        with open(public_pem, 'wb') as public_out:
            public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo))
        logging.info(f' Открытый ключ успешно сохранен в файл {public_pem}')
    except OSError as err:
        logging.warning(f' Ошибка при сохранении открытого ключа в файл {public_pem}\n{err}')

    try:
        with open(private_pem, 'wb') as private_out:
            private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                        encryption_algorithm=serialization.NoEncryption()))
        logging.info(f' закрытый ключ успешно сохранен в файл {private_pem}')
    except OSError as err:
        logging.warning(f' Ошибка при сохранении закрытого ключа в файл {private_pem}\n{err}')


def load_private_key(filename: str) -> bytes:
    """
    Функция считывает закрытый ключ из файла
    :param filename: название файла
    :return: закрытый ключ
    """
    try:
        with open(filename, mode='rb') as f:
            private_bytes = f.read()
        d_private_bytes = load_pem_private_key(private_bytes, password=None,)
        logging.info(f'Закрытый ключ считан из файла {filename}')
        return d_private_bytes
    except OSError as err:
        logging.warning(f'Ошибка при чтении из файла{filename}\n{err}')


def load_text(filename: str) -> bytes:
    """
    Функция считывает текстовый файл
    :param filename: путь к файлу
    :return: текст из файла
    """
    try:
        with open(filename, mode='rb') as f:
            text = f.read()
        logging.info(f' Файл {filename} прочитан')
    except OSError as err:
        logging.warning(f'Ошибка при чтении из файла{filename}\n{err}')
    return text


def write_file(filename: str, text: bytes) -> None:
    """
    Функция записывает текст в файл
    :param filename: путь к файлу
    :param text: текст
    :return: не возрашается
    """
    try:
        with open(filename, mode='wb') as f:
            f.write(text)
        logging.info(f' Текст записан в файл {filename}')
    except OSError as err:
        logging.warning(f' Ошибка при записи в файл {filename}\n{err}')
