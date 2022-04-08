#!/usr/bin/env python3

import re
import passwordmeter

# wordlist = [
#     "password",
#     "passwd",
#     "pswrd",
#     "pass",
#     "pwd",
#     "pw"
# ]

# reg = ".*({})[\s=(:\'\"<>]*([a-zA-Z0-9_\!\#,@\/\\\:\;.\|\`\$=\+\-\*\^\?\&\~\%]*)[\')><\"]*".format("|".join(wordlist))

# regex = re.compile(reg, re.IGNORECASE)

string_list = [
    'PASSWORD= d3v3l0p',
    'asdsd  das da passwd = checkli',
    'pwd = Password("andra")',
    "pass='cfu_lIaN8qLrcg_pssp_ZJZE8gTEEj_wap_UaJ3f7bMvY_pssp_gDJyQQIe7K_be'",
    'pw := "7erc2rrrS*2018"'
]

# for string in string_list:
#     match = regex.findall(string)
#     print(match[0][1])

for i in string_list:
    meter = passwordmeter.Meter(settings=dict(factors='length,charmix'))
    strength = meter.test(i)[0]
    print(strength)