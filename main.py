import re
import os
import json
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


def isCredentials(regex_api, data):
    regex_private_key = regex_api["private_key"]
    regex_api_creds = regex_api["other"]

    clean_match = dict()
    for key_type, values in regex_private_key.items():
        match = re.findall(values, data)
        if len(match) != 0:
            clean_match[key_type+" 1"] = match

    for api_creds_type, values in regex_api_creds.items():
        match = re.findall(values, data)
        if len(match) != 0:
            clean_match[api_creds_type] = match
    
    if len(clean_match) == 0:
        return "No API Creds Found"
    return clean_match
    # HW => after each match, remove the string from data so it will not read the same string


def getStageFile():
    repo = git.Repo()
    diff_list = repo.head.commit.diff()
    print(diff_list)


def main():
    stageFile = getStageFile()
    with open("regex.json")                 as f: regex_api = json.load(f)



    # with open("sampleFile/test.py")    as f: data = f.read()


    # print("[+] Password Check:")
    # print(isPassword(data))
    # print("\n")

    # print("[+] Api Creds Check:")
    # print(isCredentials(regex_api, data))

if __name__ == '__main__':
    main()