import argparse
import re
from cryptography.fernet import Fernet


def decrypt(filename):
    key = input("Please enter the key: ")
    # print(key)
    f = Fernet(key)
    with open(filename, "r") as file:
        encrypted = file.read()
        find_string = re.findall(r"gAAAAABi.*", encrypted)
        print(find_string)
        # exit()
        # print(encrypted)
    list_decrypted = list()
    for string in find_string:
        decrypted = f.decrypt(string.encode())
        encrypted = encrypted.replace(string, decrypted.decode())
    print(encrypted)
    # exit()
    with open(filename, "w") as file:
        # decrypted_string = encrypted.replace(
        #     find_string[0], decrypted.decode())
        file.write(encrypted)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="choose file")
    args = parser.parse_args()
    filename = args.filename
    decrypt(filename)
