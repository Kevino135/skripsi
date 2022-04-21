#!/usr/bin/env python3

import re
import os
import json
import magic
import passwordmeter
import platform
import sys
import shutil
from GitSanity.compression import *
from datetime import datetime
import pkg_resources

from cryptography.fernet import Fernet
from colorama import init, Fore, Back, Style

def getPasswordComplexity(password):
    meter = passwordmeter.Meter(settings=dict(factors="length,charmix"))
    # meter = passwordmeter.Meter()
    strength = meter.test(password)[0]

    return strength


# filter string -> only get password
def getPasswordOnly(wordlist, m_precise):
    regex_password_acc = ".*(?:{})[\s=(:'\"<>]+([a-zA-Z0-9_\!\#,@\/\\\:\;.\|\$=\+\-\*\^\?\&\~\%]*)[')><\"]*".format(
        "|".join(wordlist)
    )
    rematch = re.match(regex_password_acc, m_precise, re.IGNORECASE)

    return rematch.groups()[0]


def isPassword(read_file, read_file_lines, count_issue):
    wordlist = [
        "secret",
        "pgpassword",
        "password",
        "passwd",
        "pswrd",
        "pass",
        "pwd",
        "pw",
    ]

    # every string contains password in one line
    regex_password = ".*(?:{})[\s=(:'\"<>]+.*".format("|".join(wordlist))
    regex = re.compile(regex_password, re.IGNORECASE)

    clean_match = dict()
    for file, vals in read_file.items():
        match = regex.findall(vals)

        # assign issue if exists
        for m in match:
            m_precise = m.strip()

            rematch = getPasswordOnly(wordlist, m_precise)
            password_complexity = getPasswordComplexity(rematch)
            # print(password_complexity)

            if password_complexity >= 0.2:
                clean_match["issue " + str(count_issue)] = dict()
                clean_match["issue " + str(count_issue)]["type"] = "Password"
                clean_match["issue " + str(count_issue)]["match"] = m_precise
                clean_match["issue " + str(count_issue)]["file"] = file

                # get line number
                first = read_file_lines[file].index(m_precise) + 1
                clean_match["issue " + str(count_issue)]["line"] = str(first)

                count_issue += 1

    return clean_match


def isCredentials(regex_creds, read_file, read_file_lines):
    count_issue = 1
    clean_match = dict()

    # find creds with regex
    for regex_type, values in regex_creds.items():
        regex = re.compile(values)

        for file, vals in read_file.items():
            match = regex.findall(vals)

            # assign issue if exists
            for m in match:
                m = m.strip()

                clean_match["issue " + str(count_issue)] = dict()
                clean_match["issue " + str(count_issue)]["type"] = regex_type
                clean_match["issue " + str(count_issue)]["match"] = m
                clean_match["issue " + str(count_issue)]["file"] = file

                # get line number
                if (
                    "private" in regex_type.lower()
                    or "certificate" in regex_type.lower()
                ):
                    header = m.split("\n")[1]
                    first = (read_file_lines[file].index(header) + 1) - 1
                    last = first + len(m.split("\n")) - 1
                    clean_match["issue " + str(count_issue)][
                        "line"
                    ] = f"{first} - {last}"
                else:
                    first = read_file_lines[file].index(m) + 1
                    clean_match["issue " +
                                str(count_issue)]["line"] = str(first)

                count_issue += 1

    return clean_match, count_issue


def readModifiedFile(modified_files):
    read_file_lines = dict()
    read_file = dict()

    for file in modified_files:
        with open(file, "r") as f:
            data = f.readlines()
            data = [x.replace("\n", "").strip() for x in data]
            # data = [x for x in data if x != '']
            read_file_lines[file] = data

    for file in modified_files:
        with open(file, "r") as f:
            datas = f.read()
            read_file[file] = datas

    return read_file_lines, read_file


def getModifiedFile(extraction_path):
    # get staged file/folder
    diff_list = os.popen("git diff --name-only --cached").read()

    if diff_list == "":
        return None, None

    all_files = diff_list.strip().split("\n")

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


def selectFilesToEncrypt(final_res):
    files_to_encrypt = dict()
    print("")
    issue_input = input("Enter issues number to encrypt (ex: 1,2,5): ")
    issue_input = issue_input.split(",")
    for inputs in issue_input:
        if "issue {}".format(inputs) in final_res.keys():
            file_name = final_res["issue {}".format(inputs)]["file"]
            if file_name not in files_to_encrypt:
                files_to_encrypt[file_name] = dict()
            files_to_encrypt[file_name]["issue {}".format(inputs)] = dict()
            files_to_encrypt[file_name]["issue {}".format(inputs)]["match"] = final_res["issue {}".format(inputs)]["match"]
            files_to_encrypt[file_name]["issue {}".format(inputs)]["line"] = final_res["issue {}".format(inputs)]["line"]

    return files_to_encrypt


def getCompressedPath(compressed_file):
    compressed_path = dict()

    for key, vals in compressed_file.items():
        if vals not in compressed_path.keys():
            compressed_path[vals] = list()
        
        split_file_path = key.split("/")
        get_parent = "/".join(split_file_path[:2])

        if get_parent not in compressed_path[vals]:
            compressed_path[vals].append(get_parent)

    return compressed_path


def doEncrypt(files_to_encrypt):
    key_input = -1
    while key_input < 0 or key_input > 2:
        print("")
        print("1. Generate new key")
        print("2. Use existing generated key")
        print("0. Cancel")
        while True:
            try:
                key_input = int(input("Select [1/2/0]: "))
                break
            except ValueError:
                print("Enter an integer")
    if key_input == 1:
        enc_key = Fernet.generate_key()
        print("")
        print("Key: {}\n(Save this key, it is used for encryption and decryption)".format(enc_key.decode()))
        fernet = Fernet(enc_key)
        for file_name, issues in files_to_encrypt.items():
            with open(file_name, "r") as f:
                lines = f.read()
                for issue in issues:
                    encrypted_string = fernet.encrypt(issues[issue]["match"].encode())
                    lines = lines.replace(issues[issue]["match"], encrypted_string.decode())
            with open(file_name, "w") as f:
                f.write(lines)

    elif key_input == 2:
        print("")
        enc_key = input("Enter key: ")
        fernet = Fernet(enc_key)
        for file_name, issues in files_to_encrypt.items():
            with open(file_name, "r") as f:
                lines = f.read()
                for issue in issues:
                    encrypted_string = fernet.encrypt(issues[issue]["match"].encode())
                    lines = lines.replace(issues[issue]["match"], encrypted_string.decode())
            with open(file_name, "w") as f:
                f.write(lines)

    elif key_input == 0:
        pass

    return 1 


def doCompress(compressed_path, extraction_path):
    for target_path, extract_path in compressed_path.items():
        file_type = magic.from_file(target_path, mime=True)      
        if file_type in compression_type.keys():
            if file_type == "application/x-gzip":
                tgz = (".tar.gz", ".txt.gz", ".tgz")
                gz  = (".gz")

                if target_path.endswith(tgz):
                    compress = compression_type[file_type]["tgz"]
                elif target_path.endswith(gz):
                    compress = compression_type[file_type]["gz"]

            else:
                compress = compression_type[file_type]

            compress.compress(target_path, extract_path, extraction_path)


def printOut(final_res, compressed_file, extraction_path):
    os.system("cls" if platform.system().lower() == "windows" else "clear")

    header = " SCAN RESULT "

    print("\n" + Back.RED + Style.BRIGHT + header)
    print("=" * len(header), "\n")

    for issue, details in final_res.items():
        print(Fore.LIGHTBLUE_EX + issue.capitalize())

        for key, values in details.items():
            if key == "match":
                print("%-12s : %s%-2s" % (key.capitalize(), Fore.LIGHTGREEN_EX, values))
            elif key == "file":
                if values in compressed_file:
                    file_path = values.replace(extraction_path+"/", compressed_file[values] + " -> ")
                    print("%-12s : %-2s" % (key.capitalize(), file_path))
                else:
                    print("%-12s : %-2s" % (key.capitalize(), values))
            else:
                print("%-12s : %-2s" % (key.capitalize(), values))
        print("\n")
    

def commitAction():
    # header
    print("-"*45)
    print("| " + Back.MAGENTA + " "*13 + " COMMIT ACTION " + " "*13 + Back.RESET + " |")
    print("-"*45)
    
    print("|" + " "*2 + "1." + " "*2 + "|" + " " + "Continue with encryption"       + " "*11 + "|")
    print("|" + " "*2 + "2." + " "*2 + "|" + " " + "Continue without encryption"    + " "*8  + "|")
    print("|" + " "*2 + "0." + " "*2 + "|" + " " + "Cancel"                         + " "*29 + "|")

    # footer
    print("|" + " "*6 + "|" + " "*36 + "|")
    print("-"*45)


def main():
    # create folder to store extraction
    time_data = datetime.now()
    fmt_date = "%Y%m%d%H%M%S"

    extraction_path = datetime.strftime(time_data, fmt_date)
    if not os.path.exists(extraction_path):
        os.mkdir(extraction_path)


    # list modified file from git diff
    modified_files, compressed_file = getModifiedFile(extraction_path)

    # exit code for scan result 
    exit_code = 0
    
    if modified_files is None:
        print("\nIt seems there is no file/directories in staged\n")
    
    else:
        # get list of regex
        stream = pkg_resources.resource_string(__name__, 'regex.json')
        # with open("regex.json") as f: regex_creds = json.load(f)
        regex_creds = json.loads(stream.decode())

        # read file per line and whole file
        read_file_lines, read_file = readModifiedFile(modified_files)

        # check creds such as api, token, private key, etc
        checkCredentials, count_issue = isCredentials(regex_creds, read_file, read_file_lines)

        # check creds such as password
        checkPassword = isPassword(read_file, read_file_lines, count_issue)

        # merge dict
        final_res = {**checkCredentials, **checkPassword}
        print("\n")

        # commit action
        if final_res:
            printOut(final_res, compressed_file, extraction_path)
            continue_input = -1
            while continue_input < 0 or continue_input > 2:
                print("")
                commitAction()
                while True:
                    try:
                        if not sys.stdin.isatty():
                            sys.stdin = open('CON:', mode='r', encoding=sys.stdin.encoding)
                        continue_input = int(input("Select [1/2/0]: "))
                        break
                    except ValueError:
                        print("Enter an integer")
                    except EOFError:
                        sys.stdin.close()
                        sys.stdin = open('CON:', mode='r', encoding=sys.stdin.encoding)
                        continue

            if continue_input == 1:
                files_to_encrypt = selectFilesToEncrypt(final_res)
                compressed_path  = getCompressedPath(compressed_file)
                
                exit_code = doEncrypt(files_to_encrypt)
                doCompress(compressed_path, extraction_path)

            elif continue_input == 2:
                confirm = ""
                while confirm.lower() != "y" and confirm.lower() != "n":
                    confirm = input("Confirm to continue without encryption (Y/n): ")
                    if confirm.lower() == "y":
                        exit_code = 0
                    elif confirm.lower() == "n":
                        exit_code = 1
            elif continue_input == 0:
                exit_code = 1
        else:
            exit_code = 0

    # remove extraction path
    shutil.rmtree(extraction_path)
    return exit_code

if __name__ == "__main__":
    # initialize colorama init
    init(autoreset=True)

    main()
