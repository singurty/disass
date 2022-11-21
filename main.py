#!/usr/bin/env python3

bin_file = open("test", "rb")
bin_data = bin_file.read()

magic = bytes([0x7f, 0x45, 0x4c, 0x46])
if bin_data[:4] != magic:
    print("invalid file: not an elf binary")
    print(bin_data[:4])
    print(type(bin_data))
