from datetime import datetime
import re
import os
import shutil
import magic
from compression import *
from cryptography.fernet import Fernet



def decrypt(modified_files):
    key = input("Please enter the key: ")
    f = Fernet(key)
    for files in modified_files:
        print(files)
        with open(files, "r") as file:
            encrypted = file.read()
            find_string = re.findall(r"gAAAAABi.*", encrypted)
        
        for string in find_string:
            decrypted = f.decrypt(string.encode())
            encrypted = encrypted.replace(string, decrypted.decode())
        
        with open(files, "w") as file:
            file.write(encrypted)
   

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
    modified_files, _ = getModifiedFile(extraction_path)
    decrypt(modified_files)
    shutil.rmtree(extraction_path)


if __name__ == "__main__":
    # list modified file from git diff
    main()
