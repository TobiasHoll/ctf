import sys
import subprocess

symbols = ["stage_1", "t1_2", "t1_4", "p1_i"]
addrs = {}

for line in subprocess.run(["objdump", "-t", sys.argv[1]], check=True, capture_output=True).stdout.decode().splitlines():
    line = line.strip()
    for sym in symbols:
        if not line.endswith(f" {sym}"):
            continue
        v1 = int(line.split()[0], 16)
        assert v1, line
        addrs[sym] = v1

assert set(symbols) == set(addrs)

with open(sys.argv[2], "w") as out:
    out.write("#pragma once\n")
    for sym, addr in addrs.items():
        out.write(f"__asm__(\".equ {sym}, {addr}\\n\");\n")

