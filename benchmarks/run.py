#!/usr/bin/env python3
import os
import sys

import runner

with runner.Runner([sys.argv[1]]) as r:
    print(r.url)
    os.system("bash")
