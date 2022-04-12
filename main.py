#!/usr/bin/env python3

import re
import os
import json
import passwordmeter
import platform
import git

from cryptography.fernet import Fernet
from tabnanny import check
from colorama import init, Fore, Back, Style


def getPasswordComplexity(password):
    meter = passwordmeter.Meter(settings=dict(factors='length,charmix'))
    # meter = passwordmeter.Meter()
    strength = meter.test(password)[0]

    return strength


# filter string -> only get password
def getPasswordOnly(wordlist, m_precise):
    regex_password_acc = ".*(?:{})[\s=(:\'\"<>]+([a-zA-Z0-9_\!\#,@\/\\\:\;.\|\$=\+\-\*\^\?\&\~\%]*)[\')><\"]*".format("|".join(wordlist))
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
        "pw"
    ]

    # every string contains password in one line
    regex_password = ".*(?:{})[\s=(:\'\"<>]+.*".format("|".join(wordlist))
    regex = re.compile(regex_password, re.IGNORECASE)

    clean_match = dict()
    for file, vals in read_file.items():
        match = regex.findall(vals)
        
        # assign issue if exists
        for m in match:
            m_precise = m.strip()

            rematch             = getPasswordOnly(wordlist, m_precise)
            password_complexity = getPasswordComplexity(rematch)
            # print(password_complexity)

            if password_complexity >= 0.2:
                clean_match["issue " + str(count_issue)] = dict()
                clean_match["issue " + str(count_issue)]["type"] = "Password"
                clean_match["issue " + str(count_issue)]["match"] = m_precise
                clean_match["issue " + str(count_issue)]["file"] = file
                
                # get line number
                first = read_file_lines[file].index(m) + 1
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
                if "private" in regex_type.lower() or "certificate" in regex_type.lower():
                    header = m.split("\n")[1]
                    first = (read_file_lines[file].index(header) + 1) - 1
                    last = first + len(m.split("\n")) - 1
                    clean_match["issue " + str(count_issue)]["line"] = f"{first} - {last}"
                else:
                    first = read_file_lines[file].index(m) + 1
                    clean_match["issue " + str(count_issue)]["line"] = str(first)

                count_issue += 1

    return clean_match, count_issue


def readModifiedFile(modified_files):
    read_file_lines = dict()
    read_file       = dict()

    for file in modified_files:
        with open(file) as f:
            data = f.readlines()
            data = [x.replace("\n", "").strip() for x in data]
            # data = [x for x in data if x != '']
            read_file_lines[file] = data
    
    for file in modified_files:
        with open(file) as f:
            datas = f.read()
            read_file[file] = datas

    return read_file_lines, read_file


def getModifiedFile():
    diff_list = os.popen("git diff --name-only --cached").read()
    diff_list = diff_list.strip().split("\n")
    
    exception = ('.jpg', '.jpeg', '.png', '.gif', 
                 '.svg', '.mp4', '.mp3', '.webm', 
                 '.ttf', '.woff', '.eot', '.css', 
                 '.DS_Store','.pdf'
                )

    list_file = []

    for f in diff_list:
        if not f.endswith(exception):
            list_file.append(f)
            
    return list_file


def selectFilesToEncrypt(final_res):
    files_to_encrypt = dict()
    issue_input = input("Enter issues number to encrypt (ex: 1,2,5): ")
    issue_input = issue_input.split(",")
    for inputs in issue_input:
        if "issue {}".format(inputs) in final_res.keys():
            file_name = final_res["issue {}".format(inputs)]['file']
            if file_name not in files_to_encrypt:
                files_to_encrypt[file_name] = dict()
            files_to_encrypt[file_name]["issue {}".format(inputs)] = dict()
            files_to_encrypt[file_name]["issue {}".format(inputs)]['match'] = final_res["issue {}".format(inputs)]['match']
            files_to_encrypt[file_name]["issue {}".format(inputs)]['line'] = final_res["issue {}".format(inputs)]['line']
    
    return files_to_encrypt


def doEncryption(files_to_encrypt):
    git_repo = git.Repo(".", search_parent_directories=True)
    git_root = git_repo.git.rev_parse("--show-toplevel")
    print(git_root)


def printOut(final_res):
    os.system('cls' if platform.system().lower() == 'windows' else 'clear')

    header = " SCAN RESULT "
    
    print("\n" + Back.RED + Style.BRIGHT + header)
    print("=" * len(header), "\n")

    for issue, details in final_res.items():
        print(Fore.LIGHTBLUE_EX + issue.capitalize())
        
        for key, values in details.items():
            if key == "match":
                print("%-12s : %s%-2s" % (key.capitalize(), Fore.LIGHTGREEN_EX , values))
            else:
                print("%-12s : %-2s" % (key.capitalize(), values))
        print("\n")



def doMitigation(final_res):
    printOut(final_res)

    continue_input = 0

    while continue_input not in [1, 2, 3]:
        print("")
        print("1. Continue with encryption")
        print("2. Continue without encryption")
        print("3. Cancel")
        while True:
            try:
                continue_input = int(input("Select [1/2/3]: "))
                break
            except ValueError:
                print("Enter an integer\n")

        if continue_input == 1:
            files_to_encrypt = selectFilesToEncrypt(final_res)
            # print(files_to_encrypt)
            doEncryption(files_to_encrypt)

        elif continue_input == 2:
            confirm = ""
            while confirm.lower() not in ["y", "n"]:
                confirm = input("Confirm to continue without encryption (Y/n): ")
                if confirm.lower() == "y":
                    return 0
                elif confirm.lower() == "n":
                    return 1
        elif continue_input == 3:
            return 1


def main():
    # list modified file from git diff
    modified_files = getModifiedFile()

    # get list of regex
    with open("regex.json") as f: regex_creds = json.load(f)

    # read file per line and whole file
    read_file_lines, read_file = readModifiedFile(modified_files)

    # check creds such as api, token, private key, etc
    check_credentials, count_issue = isCredentials(regex_creds, read_file, read_file_lines)

    # check creds such as password
    check_password = isPassword(read_file, read_file_lines, count_issue)

    # merge dict
    final_res = {**check_credentials, **check_password}
    print("\n")

    if final_res:
        mitigation_decision = doMitigation(final_res)
    else:
        return 0


if __name__ == '__main__':
    # initialize colorama init
    init(autoreset = True)

    main()
