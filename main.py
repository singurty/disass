#!/usr/bin/env python3

bin_file = open("test", "rb")
bin_data = bin_file.read()

magic = bytes([0x7f, 0x45, 0x4c, 0x46])
if bin_data[:4] != magic:
    print("invalid file: not an elf binary")
    exit(1)

bit = 32
if bin_data[4] == 1:
    bit =32
elif bin_data[4] == 2:
    bit = 64
else:
    print("could not determine bit architecture")
    exit(1)

print("the program is {}-bit".format(bit))
