from enum import Enum
from program_header import Pheader

magic = bytes([0x7f, 0x45, 0x4c, 0x46])
OS = Enum("OS", ["SYSTEMV", "HPUX", "NETBSD", "LINUX", "GNUHURD", "SOLARIS", "AIX", "IRIX", 
                 "FREEBSD", "TRU64", "NOVELLMODESTO", "OPENBSD", "OPENVMS", "NONSTOPKERNEL", 
                 "AROS", "FENIXOS", "NUXICLOUDABI", "OPENVOS"])

# refer to https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#File_layout for meaning
Type = Enum("Type", ["NONE", "REL", "EXEC", "DYN", "CORE", "LOOS", "HIOS", "LOPROC", "HIPROC"])

# for e_machine. i should have used dicts for os and type too.
# i got bored of adding more stuff. that's not the goal anyway.
machine = {0x3e: "AMD x86-64"}

class Binary:
    def __init__(self, bin_data):
        if bin_data[:4] != magic:
            print("invalid file: not an elf binary")
            exit(1)
        
        if bin_data[4] == 1:
            self.bit = 32
        elif bin_data[4] == 2:
            self.bit = 64
        else:
            print("could not determine bit architecture")
            exit(1)

        # figure byteorder
        if bin_data[5] == 1:
            self.endian = "little"
        elif bin_data[5] == 2:
            self.endian = "big"
        else:
            print("invalid endianness")
            exit(1)

        if bin_data[6] != 1:
            print("invalid elf version")
            exit(1)
        
        # figure out what OS the binary is for
        if bin_data[7] == 0x00:
            self.OS = OS.SYSTEMV
        elif bin_data[7] == 0x01:
            self.OS = OS.HPUX
        elif bin_data[7] == 0x02:
            self.OS = OS.NETBSD
        elif bin_data[7] == 0x03:
            self.OS = OS.LINUX
        elif bin_data[7] == 0x04:
            self.OS = OS.GNUHURD
        elif bin_data[7] == 0x06:
            self.OS = OS.SOLARIS
        elif bin_data[7] == 0x07:
            self.OS = OS.AIX
        elif bin_data[7] == 0x08:
            self.OS = OS.IRIX
        elif bin_data[7] == 0x09:
            self.OS = OS.FREEBSD
        elif bin_data[7] == 0x0a:
            self.OS = OS.TRU64
        elif bin_data[7] == 0x0b:
            self.OS = OS.NOVELLMODESTO
        elif bin_data[7] == 0x0c:
            self.OS = OS.OPENBSD
        elif bin_data[7] == 0x0d:
            self.OS = OS.OPENVMS
        elif bin_data[7] == 0x0e:
            self.OS = OS.NONSTOPKERNEL
        elif bin_data[7] == 0x0f:
            self.OS = OS.AROS
        elif bin_data[7] == 0x10:
            self.OS = OS.FENIXOS
        elif bin_data[7] == 0x11:
            self.OS = OS.NUXICLOUDABI
        elif bin_data[7] == 0x12:
            self.OS = OS.OPENVOS
        else:
            print("invalid operating system header: {}".format(hex(bin_data[7])))
            exit(1)

        # there is no EI_ABIVERSION so treat bin_data[8] to bin_data[16] as EI_PAD
        # figure type of elf
        # e_type is two bytes
        type_bytes = int.from_bytes(bin_data[16:18], byteorder=self.endian)
        if type_bytes == 0x00:
            self.type = Type.NONE
        elif type_bytes == 0x01:
            self.type = Type.REL
        elif type_bytes == 0x02:
            self.type = Type.EXEC
        elif type_bytes == 0x03:
            self.type = Type.DYN
        elif type_bytes == 0x04:
            self.type = Type.CORE
        elif type_bytes == 0xfe00:
            self.type = Type.CORE
        elif type_bytes == 0xfeff:
            self.type = Type.HIOS
        elif type_bytes == 0xff00:
            self.type = Type.LOPROC
        elif type_bytes == 0xffff:
            self.type = Type.HIPROC
        else:
            print("invalid type header: {}".format(hex(type_bytes)))
            exit(1)

        # figure e_machine. again two bytes.
        machine_bytes = int.from_bytes(bin_data[18:20], byteorder=self.endian)
        if not machine_bytes in machine:
            print("invalid machine header: {}".format(hex(machine_bytes)))
        else:
            self.machine = machine_bytes

        # again version. bigger this time
        version_bytes = int.from_bytes(bin_data[20:24], byteorder=self.endian)
        if not version_bytes == 1:
            print("invalid elf version: {}".format(version_bytes))
            exit(1)

        # getting harder to keep track
        i = 24

        # entry is 8 bytes for 64-bit and 4 bytes for 32-bit. fuck 32-bit for now.
        # stick to goal
        self.entry = int.from_bytes(bin_data[i:i+8], byteorder=self.endian)
        i += 8

        # figure program header table pointer. size same as entry
        self.ph_off = int.from_bytes(bin_data[i:i+8], byteorder=self.endian)
        i += 8

        # figure section header table poniter. size same as entry
        self.sh_off = int.from_bytes(bin_data[i:i+8], byteorder=self.endian)
        i += 8

        # skip e_flags which is 4 bytes
        i += 4

        # figure header size
        self.header_size = int.from_bytes(bin_data[i:i+2], byteorder=self.endian)
        i += 2

        # program header entry size
        self.ph_size = int.from_bytes(bin_data[i:i+2], byteorder=self.endian)
        i += 2

        # number of entries in the program header table
        self.ph_num = int.from_bytes(bin_data[i:i+2], byteorder=self.endian)
        i += 2

        # size of a entry in section header table
        self.sh_size = int.from_bytes(bin_data[i:i+2], byteorder=self.endian)
        i += 2

        # number of entries in the section header table
        self.sh_num = int.from_bytes(bin_data[i:i+2], byteorder=self.endian)
        i += 2

        # index of the section header table entry that contains the section names
        self.sh_nameidx = int.from_bytes(bin_data[i:i+2], byteorder=self.endian)
        i += 2

        # process program headers
        self.pheaders = []
        for i in range(self.ph_num):
            off = self.ph_off + (i * self.ph_size)
            print("current offset: {}".format(off))
            self.pheaders.append(Pheader(bin_data[off:off+self.ph_size], self))

    def print_details(self):
        print("the binary is {}-bit".format(self.bit))
        print("the binary is {} endian".format(self.endian))
        print("the binary is for {}".format(OS(self.OS)))
        print("the elf type is {}".format(Type(self.type)))
        print("the machine this elf is for: {}".format(machine[self.machine]))
        print("entry pointer: {}".format(hex(self.entry)))
        print("program header pointer: {}".format(hex(self.ph_off)))
        print("elf header size: {}".format(self.header_size))
        print("program header table entry size: {}".format(self.ph_size))
        print("section header pointer: {}".format(hex(self.sh_off)))
        print("number of entries in the program header table: {}".format(self.ph_num))
        print("section header table entry size: {}".format(self.sh_size))
        print("number of entries in the section header table: {}".format(self.sh_num))
        print("index of the section header entry that contains section names: {}".format(self.sh_nameidx))

        for i in range(len(self.pheaders)):
            print("\nprogram segment: {}\n".format(i))
            self.pheaders[i].print_details()
