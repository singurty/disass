# for p_type. refer to the ELF wikipedia page for details on what these mean.
segment_types = {0x00000000: "NULL", 0x00000001: "LOAD", 0x00000002: "DYNAMIC",
                 0x00000003: "INTERP", 0x00000004: "NOTE", 0x00000005: "SHLIB",
                 0x00000006: "PHDR", 0x00000007: "TLS", 0x60000000: "OS",
                 0x70000000: "PROC"}

class Pheader:
    def __init__(self, pdata, elf):
        i = 0
        segment_type = int.from_bytes(pdata[i:i+4], byteorder=elf.endian)
        i += 4
        if not segment_type in segment_types:
            # There are two ranges of reserved values. One for OS
            # specific stuff and another for processor specific stuff.
            # We won't worry about that so we created just two entries
            # to contain both of them with the key being the low value
            # of each range.
            if segment_type > 0x60000000 and segment_type < 0x6FFFFFFF:
                segment_type = 0x60000000
            elif segment_type > 0x70000000 and segment_type < 0x7FFFFFFF:
                segment_type = 0x70000000
            else:
                print("invalid program segment type: {}".format(hex(segment_type)))
                exit(1)
        self.type = segment_type

        # Ignore segment-dependent flags which is 4 bytes. ASSUMING
        # 64-bit here. These flags are located elsewhere in 34-bit
        # binaries. Actually, we will be doing that a lot so I won't
        # warn anymore.
        i += 4

        # The offset from the beginning of the file at which the first
        # byte of the segment resides. Assuming 64-bit with the 8 bytes
        # size.
        self.offset = int.from_bytes(pdata[i:i+8], byteorder=elf.endian)
        i += 8

        # Virtual address of the segment in memory. Assuming 64-bit with the
        # 8 bytes size
        self.vaddr = int.from_bytes(pdata[i:i+8], byteorder=elf.endian)
        i += 8

        # On systems where physical address is relevant, reserved for
        # segment's physical address.
        self.paddr = int.from_bytes(pdata[i:i+8], byteorder=elf.endian)
        i += 8

        # Size in bytes of the segment in the file image. May be 0.
        self.filesz = int.from_bytes(pdata[i:i+8], byteorder=elf.endian)
        i += 8

        # Size in bytes of the segment in the memory. May be 0.
        self.memsz = int.from_bytes(pdata[i:i+8], byteorder=elf.endian)
        i += 8

        # 0 and 1 specify no alignment. Otherwise should be a positive,
        # integral power of 2, with p_vaddr equating p_offset modulus p_align.
        self.align = int.from_bytes(pdata[i:i+8], byteorder=elf.endian)
        i += 8

    def print_details(self):
        print("segment type: {}".format(segment_types[self.type]))
        print("offset: {}".format(hex(self.offset)))
        print("virtual address: {}".format(hex(self.vaddr)))
        print("physical address: {}".format(hex(self.paddr)))
        print("size of segment in file image: {}".format(hex(self.filesz)))
        print("size of segment in memory: {}".format(hex(self.memsz)))
        print("alignment: {}".format(hex(self.align)))
