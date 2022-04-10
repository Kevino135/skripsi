#!/usr/bin/env python3

import re
import passwordmeter
import platform
import os
from colorama import init, Fore, Back

# wordlist = [
#     "password",
#     "passwd",
#     "pswrd",
#     "pass",
#     "pwd",
#     "pw"
# ]

# reg = ".*({})[\s=(:\'\"<>]*([a-zA-Z0-9_\!\#,@\/\\\:\;.\|\`\$=\+\-\*\^\?\&\~\%]*)[\')><\"]*".format("|".join(wordlist))
reg = "(?:password|pass|passwd|pswrd|pwd|pw|PGPASSWORD).*['\">](.*?)['\"<]"

regex = re.compile(reg, re.IGNORECASE)

string_list = [
    'd3v3l0p70608',
    'checkli',
    'andra',
    "password_1",
    '7erc2rrrS*2018"',
    'os.getenv("PASSWORD")'
    'PASSWORD= d3v3l0p7000',
    'pwd = Password("andra")',
    "pass='cfu_lIaN8qLrcg_pssp_ZJZE8gTEEj_wap_UaJ3f7bMvY_pssp_gDJyQQIe7K_be'"
    'pw := "7erc2rrr*18"',
    'passwd = "GetDataByMemberId"',
    'if password = true',
    'if strcmp(password, "yes")',
    'password = os.getenv("PASSWORD")'
]


for string in string_list:
    match = regex.findall(string)
    print(match)

# for i in string_list:
#     meter = passwordmeter.Meter(settings=dict(factors='length,charmix'))
#     strength = meter.test(i)[0]
#     print(strength)

init()
# print(Fore.CYAN + Back.LIGHTBLACK_EX + "ANDRA")
# print(type(platform.system()))
cols, rows = os.get_terminal_size()
print(cols, rows)