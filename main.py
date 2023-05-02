import argparse
from symectric import generator_sym_key, encrypt_sym, decrypt_sym
from asymmetric import generation_asym_key, encrypt_asym, decrypt_asym
from functions_bonus import load_settings, write_sym_key, load_sym_key, write_asym_key, load_private_key,  write_file, load_text

SETTING_FILE = 'settings.json'

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-set', '--settings', default=SETTING_FILE, type=str,
                        help='Позволяет использовать собственный json-файл с указанием путей''(Введите путь к файлу)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-gen', '--generation', action='store_true', help='Запускает режим генерации ключей')
    group.add_argument('-enc', '--encryption', action='store_true', help='Запускает режим шифрования')
    group.add_argument('-dec', '--decryption', action='store_true', help='Запускает режим дешифрования')
    args = parser.parse_args()
    settings = load_settings(args.settings)
    if settings:
        if args.generation:
            sym_key = generator_sym_key()
            public_key, private_key = generation_asym_key()
            write_asym_key(public_key, private_key, settings['public_key'], settings['private_key'])
            cipher_sym_key = encrypt_asym(public_key, sym_key)
            write_sym_key(cipher_sym_key, settings['symmetric_key'])
        elif args.encryption:
            private_key = load_private_key(settings['private_key'])
            cipher_key = load_sym_key(settings['symmetric_key'])
            symectric_key = decrypt_asym(private_key, cipher_key)
            text = load_text(settings['initial_file'])
            cipher_text = encrypt_sym(symectric_key, text)
            write_file(settings['encrypted_file'], cipher_text)
        else:
            private_key = load_private_key(settings['private_key'])
            cipher_key = load_sym_key(settings['symmetric_key'])
            symmetric_key = decrypt_asym(private_key, cipher_key)
            cipher_text = load_text(settings['encrypted_file'])
            text = decrypt_sym(symmetric_key, cipher_text)
            write_file(settings['decrypted_file'], text)
