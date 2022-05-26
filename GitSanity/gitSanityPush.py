import re
import os
from tkinter import *
from tkinter import ttk
from cryptography.fernet import Fernet



def detectEncryptedString(modified_files):
    files_containing_encrypted_string = list()

    for files in modified_files:
        with open(files, "r") as file:
            content = file.read()
            if "gAAAAABi" in content:
                files_containing_encrypted_string.append(files)
    
    return files_containing_encrypted_string


def showDecryptWindow(files_containing_encrypted_string):

    def doDecrypt():
        f = Fernet(decryption_key_entry.get())
        for files in files_containing_encrypted_string:
            with open(files, "r") as file:
                encrypted = file.read()
                find_string = re.findall(r"gAAAAABi.*", encrypted)
            
            plaintext = encrypted
            for string in find_string:
                decrypted = f.decrypt(string.encode())
                plaintext = plaintext.replace(string, decrypted.decode())
            
            with open(files, "w") as file:
                file.write(plaintext)

        closeRoot()

    
    def closeRoot():
        global exit_code
        exit_code = 0
        root.destroy()


    root = Tk()
    root.title("Decrypt")

    lbl = ttk.Label(root, text="Detected encrypted string, please enter decryption key:")
    lbl.grid(column=0, row=0)

    decryption_key_entry = Entry(root, width=50)
    decryption_key_entry.grid(column=0, row=1)

    Button(root, text="Submit", command=doDecrypt).grid(column=0, row=2)

    root.mainloop()
   

def getModifiedFile():
    # get staged file/folder
    git_root_path = os.popen("git rev-parse --show-toplevel").read()
    git_root_path = git_root_path.replace("\n","")
    all_files = list()

    for root, dirs, files in os.walk(git_root_path, topdown=False):
        for name in files:
            path = os.path.join(root, name).replace(git_root_path + "\\", "").replace(git_root_path + "/" , "")
            if (".git" not in path) and ("__pycache__" not in path):
                all_files.append(path)
    
    file_ignore = (
        ".jpg", ".jpeg", ".png", ".gif", ".svg",
        ".mp4", ".mp3", ".webm", ".ttf", ".woff",
        ".eot", ".css", ".DS_Store", ".pdf",
    )

    # filtering
    filtered_file = list()
    for files in all_files:
        if not files.endswith(file_ignore):
            filtered_file.append(files)
    
    return filtered_file


def main():
    global exit_code
    exit_code = 0
    
    modified_files = getModifiedFile()

    files_containing_encrypted_string = detectEncryptedString(modified_files)
    if files_containing_encrypted_string:
        os.popen("git push --no-verify")
        showDecryptWindow(files_containing_encrypted_string)

    return exit_code


if __name__ == "__main__":
    # list modified file from git diff
    exit_code = 0
    main()
