segment_types = {
        0x0: "NULL",
        0x1: "PROGBITS",
        0x2: "SYMTAB",
        0x3: "STRTAB",
        0x4: "RELA",
        0x5: "HASH",
        0x6: "DYNAMIC",
        0x7: "NOTE",
        0x8: "NOBITS",
        0x9: "REL",
        0x0a: "SHLIB",
        0x0b: "DYNSYM",
        0x0e: "INIT_ARRAY",
        0x0f: "FINI_ARRAY",
        0x10: "PREINIT_ARRAY",
        0x11: "GROUP",
        0x12: "SYMTAB_SHNDX",
        0x13: "NUM",
        0x60000000: "OS"
        }
attributes = {
        0x1: "WRITE",
        0x2: "ALLOC",
        0x4: "EXECINSTR",
        0x10: "MERGE",
        0x20: "STRINGS",
        0x40: "INFO_LINK",
        0x80: "LINK_ORDER",
        0x100: "OS_NONCONFORMING",
        0x200: "GROUP",
        0x400: "TLS",
        0x0FF00000: "MASKOS",
        0xF0000000: "MASKPROC",
        0x4000000: "ORDERED",
        0x8000000: "EXCLUDE"
        }

class Sheader:
    def __init__(self, sdata, elf):
        i = 0
        self.name = int.from_bytes(sdata[i:i+4], byteorder=elf.endian)
        i += 4

        segment_type = int.from_bytes(sdata[i:i+4], byteorder=elf.endian)
        i += 4
        if not segment_type in segment_types:
            # Type values above this are OS-specific
            if segment_type > 0x60000000:
                segment_type = 0x60000000
            else:
                print("invalid program segment type: {}".format(hex(segment_type)))
                exit(1)
        self.type = segment_type

        # process flags
        self.flags = int.from_bytes(sdata[i:i+8], byteorder=elf.endian)
        i += 8

        # Virtual address of the segment in memory. Assuming 64-bit with the
        # 8 bytes size
        self.vaddr = int.from_bytes(sdata[i:i+8], byteorder=elf.endian)
        i += 8

        # The offset from the beginning of the file at which the first
        # byte of the segment resides. Assuming 64-bit with the 8 bytes
        # size.
        self.offset = int.from_bytes(sdata[i:i+8], byteorder=elf.endian)
        i += 8

        # Size in bytes of the segment in the file image. May be 0.
        self.size = int.from_bytes(sdata[i:i+8], byteorder=elf.endian)
        i += 8

        self.link = int.from_bytes(sdata[i:i+4], byteorder=elf.endian)
        i += 4

        self.info = int.from_bytes(sdata[i:i+4], byteorder=elf.endian)
        i += 4

        self.addralign = int.from_bytes(sdata[i:i+8], byteorder=elf.endian)
        i += 8

        self.entsize = int.from_bytes(sdata[i:i+8], byteorder=elf.endian)
        i += 8

    def print_details(self):
        print("segment type: {}".format(segment_types[self.type]))
        print("flags: {}".format(hex(self.flags)))
        print("virtual address: {}".format(hex(self.vaddr)))
        print("offset: {}".format(hex(self.offset)))
        print("size of segment in file image: {}".format(hex(self.size)))
        print("link: {}".format(hex(self.link)))
        print("info: {}".format(hex(self.info)))
        print("align: {}".format(hex(self.addralign)))
        print("entry size: {}".format(hex(self.entsize)))
