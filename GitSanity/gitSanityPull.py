from datetime import datetime
import re
import os
import shutil
import magic
from tkinter import *
from tkinter import ttk
from GitSanity.compression import *
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
            print(files)
            with open(files, "r") as file:
                encrypted = file.read()
                find_string = re.findall(r"gAAAAABi.*", encrypted)
            
            for string in find_string:
                decrypted = f.decrypt(string.encode())
                plaintext = encrypted.replace(string, decrypted.decode())
            
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
   

def getModifiedFile(extraction_path):
    # get staged file/folder
    git_root_path = os.popen("git rev-parse --show-toplevel").read()
    git_root_path = git_root_path.replace("\n","")
    all_files = list()

    for root, dirs, files in os.walk(git_root_path, topdown=False):
        for name in files:
            path = os.path.join(root, name).replace(git_root_path + "\\", "").replace(git_root_path + "/" , "")
            if (".git" not in path) and ("__pycache__" not in path):
                all_files.append(path)
    
    # extraction
    compressed_file = dict()
    for files in all_files:
        file_type = magic.from_file(files, mime=True)      
        if file_type in compression_type.keys():
            if file_type == "application/x-gzip":
                tgz = (".tar.gz", ".txt.gz", ".tgz")
                gz  = (".gz")

                if files.endswith(tgz):
                    decompress = compression_type[file_type]["tgz"]
                elif files.endswith(gz):
                    decompress = compression_type[file_type]["gz"]

            else:
                decompress = compression_type[file_type]

            decompress.decompress(files, extraction_path)

            list_decompress = [extraction_path + f"/{x}" for x in decompress.list(files)]
            for f in list_decompress:
                if os.path.isfile(f):
                    compressed_file[f] = files

    # remove compressed file and add its extraction to list
    for key, vals in compressed_file.items():
        if vals in all_files:
            all_files.remove(vals)
        all_files.append(key)

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
    
    return filtered_file, compressed_file


def main():
    time_data = datetime.now()
    fmt_date = "%Y%m%d%H%M%S"
    
    extraction_path = datetime.strftime(time_data, fmt_date)
    if not os.path.exists(extraction_path):
        os.mkdir(extraction_path)

    modified_files, compressed_file = getModifiedFile(extraction_path)

    files_containing_encrypted_string = detectEncryptedString(modified_files)
    if files_containing_encrypted_string:
        showDecryptWindow(files_containing_encrypted_string)

    shutil.rmtree(extraction_path)

    return exit_code


if __name__ == "__main__":
    # list modified file from git diff
    exit_code = 0
    main()
