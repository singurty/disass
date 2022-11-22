from enum import Enum

magic = bytes([0x7f, 0x45, 0x4c, 0x46])
OS = Enum("OS", ["SYSTEMV", "HPUX", "NETBSD", "LINUX", "GNUHURD", "SOLARIS", "AIX", "IRIX", 
                 "FREEBSD", "TRU64", "NOVELLMODESTO", "OPENBSD", "OPENVMS", "NONSTOPKERNEL", 
                 "AROS", "FENIXOS", "NUXICLOUDABI", "OPENVOS"])

# refer to https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#File_layout for meaning
Type = Enum("Type", ["NONE", "REL", "EXEC", "DYN", "CORE", "LOOS", "HIOS", "LOPROC", "HIPROC"])

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

        # 1 is little, 2 is big
        self.endian = bin_data[5]
        if not self.endian == 1 or self.endian == 2:
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

        # there is no EI_ABIVERSION so treat bin_data[7] to bin_data[15] as EI_PAD
        # figure type of elf
        # e_type is two bytes
        type_bytes = int.from_bytes(bin_data[15:17], byteorder="big")
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
    def print_details(self):
        print("the binary is {}-bit".format(self.bit))
        if self.endian == 1:
            print("the binary is little endian")
        else:
            print("the binary is big endian")
        print("the binary is for {}".format(OS(self.OS)))
        print("the elf type is {}".format(Type(self.type)))
