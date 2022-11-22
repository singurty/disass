#!/usr/bin/env python3
from binary import Binary

bin_file = open("helloworld", "rb")
bin_data = bin_file.read()
binary = Binary(bin_data)
binary.print_details()
