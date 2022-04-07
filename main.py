import re
import os
import json
from tabnanny import check
import git


def isPassword(data):
    wordlist = [
        "password",
        "passwd",
        "pswrd",
        "pass",
        "pwd",
        "pw"
    ]

    regex_variable = '.*\s:?={1,}\s.*'
    dirty_match = re.findall(regex_variable, data)
    dirty_match = [x.replace("\t", "") for x in dirty_match]

    clean_match = list()
    for variable in dirty_match:
        for word in wordlist:
            if word in variable:
                clean_match.append(variable)
                break

    if len(clean_match) == 0:
        return "No Password Found"
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
                clean_match["issue " + str(count_issue)] = dict()
                clean_match["issue " + str(count_issue)]["type"] = regex_type
                clean_match["issue " + str(count_issue)]["match"] = m
                clean_match["issue " + str(count_issue)]["file"] = file
                
                # get line number
                if "private" in regex_type:
                    header = m.split("\n")[1]
                    first = (read_file_lines[file].index(header) + 1) - 1
                    last = first + len(m.split("\n")) - 1
                    clean_match["issue " + str(count_issue)]["line"] = f"{first} - {last}"
                else:
                    first = (read_file_lines[file].index(m) + 1) - 1
                    clean_match["issue " + str(count_issue)]["line"] = str(first)

                count_issue += 1

    for k, v in clean_match.items():
        print(k, v, "\n")
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
    diff_list = repo.git.diff('HEAD', name_only=True)
    
    return diff_list.split('\n')


def main():
    # list modified file from git diff
    modified_files = getModifiedFile()

    # get list of regex
    with open("regex.json") as f: regex_creds = json.load(f)

    # read file per line and whole file
    read_file_lines, read_file = readModifiedFile(modified_files)

    print("[+] Api Creds Check:")
    checkCredentials, count_issue = isCredentials(regex_creds, read_file, read_file_lines)
    # print(checkCredentials)
    # print("[+] Password Check:")
    # print(isPassword(data))
    # print("\n")



if __name__ == '__main__':
    main()