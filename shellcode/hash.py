#!/usr/bin/python3
import sys

def ror(byte, count):
    binb = bin(byte)[2:].zfill(32)
    binb = binb[-count % 32:] + binb[:-count % 32]
    return int(binb, 2)

esi = sys.argv[1]
edx = 0x0

counter = 0

for eax in esi:
    edx = edx + ord(eax)
    if counter < len(esi) - 1:
        edx = ror(edx, 47)
        counter += 1

print(hex(edx))
