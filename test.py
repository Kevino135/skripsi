#!/usr/bin/env python3

import re

reg = r"\".*:.*@tcp\([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,6}\)\/.*\""

ss = "aurora: \"Phars:d3v3l0@tcp(34.87.44.167:3306)/q_love?parseTime=true\""
s = re.findall(reg, ss)

print(s)