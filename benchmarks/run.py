#!/usr/bin/env python3
import runner
import sys
import os

with runner.Runner(sys.argv[1]) as r:
    print(r.url)
    os.system("bash")
