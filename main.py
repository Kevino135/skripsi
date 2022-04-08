#!/usr/bin/env python3

import re
import os
import json
import passwordmeter
from tabnanny import check
import git


class colors:
    reset = "\033[0m"

    # Black
    fgBlack = "\033[30m"
    fgBrightBlack = "\033[30;1m"
    bgBlack = "\033[40m"
    bgBrightBlack = "\033[40;1m"

    # Red
    fgRed = "\033[31m"
    fgBrightRed = "\033[31;1m"
    bgRed = "\033[41m"
    bgBrightRed = "\033[41;1m"

    # Green
    fgGreen = "\033[32m"
    fgBrightGreen = "\033[32;1m"
    bgGreen = "\033[42m"
    bgBrightGreen = "\033[42;1m"

    # Yellow
    fgYellow = "\033[33m"
    fgBrightYellow = "\033[33;1m"
    bgYellow = "\033[43m"
    bgBrightYellow = "\033[43;1m"

    # Blue
    fgBlue = "\033[34m"
    fgBrightBlue = "\033[34;1m"
    bgBlue = "\033[44m"
    bgBrightBlue = "\033[44;1m"

    # Magenta
    fgMagenta = "\033[35m"
    fgBrightMagenta = "\033[35;1m"
    bgMagenta = "\033[45m"
    bgBrightMagenta = "\033[45;1m"

    # Cyan
    fgCyan = "\033[36m"
    fgBrightCyan = "\033[36;1m"
    bgCyan = "\033[46m"
    bgBrightCyan = "\033[46;1m"

    # White
    fgWhite = "\033[37m"
    fgBrightWhite = "\033[37;1m"
    bgWhite = "\033[47m"
    bgBrightWhite = "\033[47;1m"


def getPasswordComplexity(password):
    meter = passwordmeter.Meter(settings=dict(factors='length,charmix'))
    # meter = passwordmeter.Meter()
    strength = meter.test(password)[0]

    return strength


# filter string -> only get password
def getPasswordOnly(wordlist, m_precise):
    regex_password_acc = ".*({})[\s=(:\'\"<>]*([a-zA-Z0-9_\!\#,@\/\\\:\;.\|\$=\+\-\*\^\?\&\~\%]*)[\')><\"]*".format("|".join(wordlist))
    rematch = re.findall(regex_password_acc, m_precise, re.IGNORECASE)

    return rematch[0][1]


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
    regex_password = ".*{}.*".format(".*|.*".join(wordlist))
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
    repo = git.Repo()
    diff_list = repo.git.diff('HEAD', name_only=True, cached=True)
    
    return diff_list.split('\n')


def printOut(final_res):
    for issue, details in final_res.items():
        print(colors.fgBrightBlue + issue.capitalize() + colors.reset)
        
        for key, values in details.items():
            if key == "match":
                print("%-12s : %s%-2s%s" % (key.capitalize(), colors.fgBrightGreen, values, colors.reset))
            else:
                print("%-12s : %-2s" % (key.capitalize(), values))
        print("\n")


def main():
    # list modified file from git diff
    modified_files = getModifiedFile()

    # get list of regex
    with open("regex.json") as f: regex_creds = json.load(f)

    # read file per line and whole file
    read_file_lines, read_file = readModifiedFile(modified_files)

    # check creds such as api, token, private key, etc
    checkCredentials, count_issue = isCredentials(regex_creds, read_file, read_file_lines)

    # check creds such as password
    checkPassword = isPassword(read_file, read_file_lines, count_issue)

    # merge dict
    final_res = {**checkCredentials, **checkPassword}
    print("\n")

    # print
    printOut(final_res)


if __name__ == '__main__':
    main()