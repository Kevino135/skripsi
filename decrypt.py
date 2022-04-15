import argparse
import re
from cryptography.fernet import Fernet


def decrypt(filename):
    key = input("Please enter the key: ")
    f = Fernet(key)
    
    with open(filename, "r") as file:
        encrypted = file.read()
        find_string = re.findall(r"gAAAAABi.*", encrypted)
    
    for string in find_string:
        decrypted = f.decrypt(string.encode())
        encrypted = encrypted.replace(string, decrypted.decode())
    
    with open(filename, "w") as file:
        file.write(encrypted)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="choose file")
    args = parser.parse_args()
    filename = args.filename
    decrypt(filename)
