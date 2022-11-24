# for p_type. refer to the ELF wikipedia page for details on what these mean.
segment_types = {0x00000000: "PT_NULL", 0x00000001: "PT_LOAD", 0x00000002: "PT_DYNAMIC",
                 0x00000003: "PT_INTERP", 0x00000004: "PT_NOTE", 0x00000005: "PT_SHLIB",
                 0x00000006: "PT_PHDR", 0x00000007: "PT_TLS", 0x60000000: "PT_OS",
                 0x70000000: "PT_PROC"}

class Pheader:
    def __init__(self, pdata, elf):
        i = 0
        segment_type = int.from_bytes(pdata[i:i+4], byteorder=elf.endian)
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

    def print_details(self):
        print("segment type: {}".format(segment_types[self.type]))
