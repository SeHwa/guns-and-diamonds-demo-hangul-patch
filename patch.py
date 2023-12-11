import os
import copy
import gzip
import shutil
import struct
import codecs
from functools import reduce
from keystone import *
from keystone.mips_const import *
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section

p8 = lambda x: struct.pack("<B", x)
p16 = lambda x: struct.pack("<H", x)
p32 = lambda x: struct.pack("<I", x)
u16 = lambda x: struct.unpack("<H", x)[0]
u32 = lambda x: struct.unpack("<I", x)[0]

def patch(data, offset, patch_data):
    return data[:offset] + patch_data + data[offset + len(patch_data):]

class PACK:
    def __init__(self, fn_or_data):
        if type(fn_or_data) == str:
            self.data = open(fn_or_data, "rb").read()
        else:
            self.data = fn_or_data

    def save(self, fn = None):
        if fn == None: return self.data
        open(fn, "wb").write(self.data)

    def list(self):
        names = []
        ptr = 0x10
        while True:
            if ptr >= len(self.data): break
            name_len = u32(self.data[ptr+0x8:ptr+0xC])
            name = self.data[ptr+0x10:ptr+0x10+name_len].decode("utf-8").strip("\x00")
            names.append(name)
            size = u32(self.data[ptr+0x4:ptr+0x8])
            ptr += size + 0x10
        return names

    def unpack(self, filename):
        filedata = b""
        ptr = 0x10
        while True:
            if ptr >= len(self.data): break
            name_len = u32(self.data[ptr+0x8:ptr+0xC])
            name = self.data[ptr+0x10:ptr+0x10+name_len].decode("utf-8").strip("\x00")
            size = u32(self.data[ptr+0x4:ptr+0x8])
            flag = self.data[ptr+0x1]
            if name == filename:
                filedata = self.data[ptr+0x10+name_len:ptr+0x10+size]
                if flag & 1 != 0:
                    filedata = gzip.decompress(filedata)
                break
            ptr += size + 0x10
        return filedata

    def pack(self, filename, filedata, opt = 0, addr = 0):
        ptr = 0x10
        while True:
            if ptr >= len(self.data): break
            name_len = u32(self.data[ptr+0x8:ptr+0xC])
            name = self.data[ptr+0x10:ptr+0x10+name_len].decode("utf-8").strip("\x00")
            size = u32(self.data[ptr+0x4:ptr+0x8])
            flag = self.data[ptr+0x1]
            if name == filename:
                if flag & 1 != 0:
                    filedata = gzip.compress(filedata)
                    if len(filedata) < size - name_len:
                        filedata += b"\x00"*(size - name_len - len(filedata))
                    else:
                        filedata = patch(filedata[:size - name_len], 0, p32(0x77777777) + p32(addr))

                if opt == 1:
                    header = self.data[ptr:ptr+0x10+name_len]
                    self.data = patch(self.data, ptr+0x10, b"\x00"*name_len)
                    self.data = patch(self.data, ptr+0x2, b"\xFF\xFF")

                    ptr = len(self.data)
                    self.data += header
                    self.data += filedata
                else:
                    self.data = self.data[:ptr+0x10+name_len] + filedata + self.data[ptr+0x10+size:]

                self.data = patch(self.data, ptr+0x4, p32(len(filedata) + name_len))
                break
            ptr += size + 0x10

class GIM2:
    def __init__(self, fn_or_data):
        if type(fn_or_data) == str:
            self.data = open(fn_or_data, "rb").read()
        else:
            self.data = fn_or_data

    def save(self, fn = None):
        if fn == None: return self.data
        open(fn, "wb").write(self.data)

    def list(self):
        names = []
        ptr = 0x0
        while True:
            if ptr >= len(self.data): break
            name_len = u32(self.data[ptr+0x8:ptr+0xC])
            name = self.data[ptr+0x10:ptr+0x10+name_len].decode("utf-8").strip("\x00")
            names.append(name)
            size = u32(self.data[ptr+0x0C:ptr+0x10])
            ptr += size + 0x20
        return names

    def unpack(self, gimname):
        gimdata = b""
        ptr = 0x0
        while True:
            if ptr >= len(self.data): break
            name_len = u32(self.data[ptr+0x8:ptr+0xC])
            name = self.data[ptr+0x10:ptr+0x10+name_len].decode("utf-8").strip("\x00")
            size = u32(self.data[ptr+0xC:ptr+0x10])
            if name == gimname:
                gimdata = self.data[ptr+0x10+name_len:ptr+0x10+name_len+size]
                break
            ptr += size + 0x20
        return gimdata

    def pack(self, gimname, gimdata, opt = 0):
        ptr = 0x0
        while True:
            if ptr >= len(self.data): break
            name_len = u32(self.data[ptr+0x8:ptr+0xC])
            name = self.data[ptr+0x10:ptr+0x10+name_len].decode("utf-8").strip("\x00")
            size = u32(self.data[ptr+0xC:ptr+0x10])
            if name == gimname:
                if opt == 1:
                    header = self.data[ptr:ptr+0x10+name_len]
                    self.data = patch(self.data, ptr+0x10, b"\x00"*name_len)

                    ptr = len(self.data)
                    self.data += header
                    self.data += gimdata
                else:
                    self.data = self.data[:ptr+0x10+name_len] + gimdata + self.data[ptr+0x10+name_len+size:]

                self.data = patch(self.data, ptr+0xC, p32(len(gimdata)))
                break
            ptr += size + 0x20

def data_aligned(self):
    if self.data_size % self.data_alignment == 0:
        return self.data()
    return self.data().ljust(self.data_size + self.data_alignment - (self.data_size % self.data_alignment), b"\x00")

def get_section_header_raw(h):
        sh_type_int = {"SHT_NULL": 0, "SHT_PROGBITS": 1, "SHT_SYMTAB": 2, "SHT_STRTAB": 3, "SHT_RELA": 4, "SHT_HASH": 5, "SHT_DYNAMIC": 6, "SHT_NOTE": 7, "SHT_NOBITS": 8, "SHT_REL": 9, "SHT_SHLIB": 0xA, "SHT_DYNSYM": 0xB, "SHT_INIT_ARRAY": 0xE, "SHT_FINI_ARRAY": 0xF, "SHT_PREINIT_ARRAY": 0x10, "SHT_GROUP": 0x11, "SHT_SYMTAB_SHNDX": 0x12, "SHT_NUM": 0x13}

        sh_type = 0
        if type(h.sh_type) == str:
            sh_type = sh_type_int[h.sh_type]
        else:
            sh_type = h.sh_type

        return p32(h.sh_name) + p32(sh_type) + p32(h.sh_flags) + p32(h.sh_addr) + p32(h.sh_offset) + p32(h.sh_size) + p32(h.sh_link) + p32(h.sh_info) + p32(h.sh_addralign) + p32(h.sh_entsize)

def get_segment_header_raw(h):
    p_type_int = {"PT_NULL": 0, "PT_LOAD": 1, "PT_DYNAMIC": 2, "PT_INTERP": 3, "PT_NOTE": 4, "PT_SHLIB": 5, "PT_PHDR": 6, "PT_TLS": 7}

    p_type = 0
    if type(h.p_type) == str:
        p_type = p_type_int[h.p_type]
    else:
        p_type = h.p_type

    return p32(p_type) + p32(h.p_offset) + p32(h.p_vaddr) + p32(h.p_paddr) + p32(h.p_filesz) + p32(h.p_memsz) + p32(h.p_flags) + p32(h.p_align)

setattr(Section, "data_aligned", data_aligned)

shutil.copyfile("NPJG-90040/PSP_GAME/SYSDIR/EBOOT.BIN", "NPJG-90040_kor/PSP_GAME/SYSDIR/EBOOT.BIN")
shutil.copyfile("NPJG-90040/PSP_GAME/USRDIR/pack/ep07_101.dat", "NPJG-90040_kor/PSP_GAME/USRDIR/pack/ep07_101.dat")
shutil.copyfile("NPJG-90040/PSP_GAME/USRDIR/pack/ep07_102.dat", "NPJG-90040_kor/PSP_GAME/USRDIR/pack/ep07_102.dat")
shutil.copyfile("NPJG-90040/PSP_GAME/USRDIR/pack/ep07_103.dat", "NPJG-90040_kor/PSP_GAME/USRDIR/pack/ep07_103.dat")
shutil.copyfile("NPJG-90040/PSP_GAME/USRDIR/pack/ep07_110.dat", "NPJG-90040_kor/PSP_GAME/USRDIR/pack/ep07_110.dat")
shutil.copyfile("NPJG-90040/PSP_GAME/USRDIR/pack/static.dat", "NPJG-90040_kor/PSP_GAME/USRDIR/pack/static.dat")
shutil.copyfile("NPJG-90040/PSP_GAME/USRDIR/pack/title.dat", "NPJG-90040_kor/PSP_GAME/USRDIR/pack/title.dat")

data = open("BOOT.BIN", "rb").read()
elf = ELFFile(open("BOOT.BIN", "rb"))
sect = list(elf.iter_sections())
seg = list(elf.iter_segments())
sect_headers = [ s.header for s in sect ]

e = elf._parse_elf_header()
data = patch(data, 0x20, p32(len(data)))
data = patch(data, 0x30, p16(e.e_shnum + 2))

origsize = len(data)
new_sectsize = e.e_shentsize * (e.e_shnum + 2)
datasectsize = len(sect[49].data_aligned() + sect[51].data_aligned() + sect[52].data_aligned())
p_vaddr = seg[1].header.p_vaddr
p_memsz = seg[1].header.p_memsz

new_sect1_header = sect[3].header.copy()
new_sect1_header.sh_addr = p_vaddr + p_memsz
new_sect1_header.sh_offset = origsize + new_sectsize + datasectsize + (p_memsz - datasectsize)
new_sect1_header.sh_size = 0x10000

new_sect2_header = sect[49].header.copy()
new_sect2_header.sh_addr = p_vaddr + p_memsz + 0x10000
new_sect2_header.sh_offset = origsize + new_sectsize + datasectsize + (p_memsz - datasectsize) + 0x10000
new_sect2_header.sh_size = 0x10000

sect_headers = copy.deepcopy(sect_headers) + [new_sect1_header, new_sect2_header]
sect_headers[49].sh_offset = origsize + new_sectsize
sect_headers[51].sh_offset = origsize + new_sectsize + len(sect[49].data_aligned())
sect_headers[52].sh_offset = origsize + new_sectsize + len(sect[49].data_aligned()) + len(sect[51].data_aligned())
data = reduce(lambda x, y: x + get_section_header_raw(y), sect_headers, data)

seg[1].header.p_offset = origsize + new_sectsize
seg[1].header.p_memsz += 0x20000
seg[1].header.p_filesz = seg[1].header.p_memsz
seg[1].header.p_flags = 0x7
data = patch(data, e.e_phoff + (e.e_phentsize * 1), get_segment_header_raw(seg[1].header))

data += sect[49].data_aligned()
data += sect[51].data_aligned()
data += sect[52].data_aligned()
data += b"\x00" * (p_memsz - datasectsize)

ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32)
ELF_BASE = 0x8804000
TEXTSECTION_BASE = 0xC0
newcode_baseaddr = p_vaddr + p_memsz
code_all = b""

asm = '''
move $v0, $a0
move $v1, $a2
addiu $v0, $v0, -0x1
lbu $t7, 0($v1)
andi $t7, $t7, 0xF0
li $t8, 0xC0
beq $t7, $t8, utf16
li $t8, 0xD0
beq $t7, $t8, utf16
j ''' + hex(ELF_BASE + 0x6E408) + '''
utf16:
beq $s7, $zero, normal

lw $t5, ''' + hex(ELF_BASE + newcode_baseaddr - 0x8) + '''
li $t7, 0x8
beq $t5, $t7, onizka
addiu $t7, $t7, -0x1
beq $t5, $t7, katagiri
addiu $t7, $t7, -0x1
beq $t5, $t7, nakamura
addiu $t7, $t7, -0x1
beq $t5, $t7, kanjaki

normal:
lbu $t7, 0($v1)
addiu $t7, $t7, -0xC0
sll $t7, $t7, 0x1
copy:
addiu $v0, $v0, 0x1
addiu $v1, $v1, 0x1
lbu $t8, 0($v1)
sb $t8, 0($v0)
addiu $t7, $t7, -0x1
bne $t7, $zero, copy

li $t7, 0x4
beq $t5, $t7, onizka2
addiu $t7, $t7, -0x1
beq $t5, $t7, katagiri2
addiu $t7, $t7, -0x1
beq $t5, $t7, nakamura2
addiu $t7, $t7, -0x1
beq $t5, $t7, money
jr $ra

onizka:
addiu $v0, $v0, 0x1
li $t7, 0xb2c8c624
sw $t7, 0($v0)
li $t7, 0xce74c988
sw $t7, 4($v0)
sb $zero, 8($v0)
jr $ra

katagiri:
addiu $v0, $v0, 0x1
li $t7, 0xd0c0ce74
sw $t7, 0($v0)
li $t7, 0xb9acae30
sw $t7, 4($v0)
sb $zero, 8($v0)
jr $ra

nakamura:
addiu $v0, $v0, 0x1
li $t7, 0xce74b098
sw $t7, 0($v0)
li $t7, 0xb77cbb34
sw $t7, 4($v0)
sb $zero, 8($v0)
jr $ra

kanjaki:
addiu $v0, $v0, 0x1
li $t7, 0xc790ce78
sw $t7, 0($v0)
li $t7, 0x0000d0a4
sw $t7, 4($v0)
jr $ra

onizka2:
move $v0, $a0
li $t7, 0xc12dad50
sw $t7, 0($v0)
li $t7, 0x58
sb $t7, 22($v0)
li $t7, 0xce
sb $t7, 23($v0)
sb $zero, 24($v0)
jr $ra

katagiri2:
move $v0, $a0
li $t7, 0xb85cc81c
sw $t7, 0($v0)
li $t7, 0xe0
sb $t7, 30($v0)
li $t7, 0xcf
sb $t7, 31($v0)
sb $zero, 32($v0)
jr $ra

nakamura2:
move $v0, $a0
li $t7, 0xbcf4c815
sw $t7, 0($v0)
li $t7, 0xa4
sb $t7, 30($v0)
li $t7, 0xc2
sb $t7, 31($v0)
sb $zero, 32($v0)
li $t7, 0xcf
sb $t7, 33($v0)
sb $zero, 34($v0)
jr $ra

money:
move $v0, $a0
li $t7, 0xc561ae08
sw $t7, 0($v0)
li $t7, 0x5c
sb $t7, 10($v0)
li $t7, 0xd5
sb $t7, 11($v0)
li $t7, 0xe4
sb $t7, 12($v0)
li $t7, 0xb2
sb $t7, 13($v0)
sb $zero, 14($v0)
jr $ra
'''
code, cnt = ks.asm(asm)
code_all += b"".join(map(p8, code)).ljust(0x500, b"\x00")

asm = '''
lbu $t7, 0($a0)
andi $t7, $t7, 0xF0
li $t8, 0xC0
beq $t7, $t8, utf16
li $t8, 0xD0
beq $t7, $t8, utf16
j ''' + hex(ELF_BASE + 0x6E424) + '''
utf16:
lbu $t7, 0($a0)
addiu $t7, $t7, -0xC0
addiu $t7, $t7, 0x8
move $v0, $t7

move $t5, $zero
move $t7, $zero
lbu $t8, 1($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 2($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 3($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 4($a0)
or $t7, $t7, $t8
li $t8, 0x24c624c6
beq $t7, $t8, onizka

move $t7, $zero
lbu $t8, 1($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 2($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 3($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 4($a0)
or $t7, $t7, $t8
li $t8, 0x74ce74ce
beq $t7, $t8, katagiri

move $t7, $zero
lbu $t8, 1($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 2($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 3($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 4($a0)
or $t7, $t7, $t8
li $t8, 0x98b098b0
beq $t7, $t8, nakamura

move $t7, $zero
lbu $t8, 1($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 2($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 3($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 4($a0)
or $t7, $t7, $t8
li $t8, 0x78ce78ce
beq $t7, $t8, kanjaki

move $t7, $zero
lbu $t8, 1($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 2($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 3($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 4($a0)
or $t7, $t7, $t8
li $t8, 0x50ad50ad
beq $t7, $t8, onizka2

move $t7, $zero
lbu $t8, 1($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 2($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 3($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 4($a0)
or $t7, $t7, $t8
li $t8, 0x1cc81cc8
beq $t7, $t8, katagiri2

move $t7, $zero
lbu $t8, 1($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 2($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 3($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 4($a0)
or $t7, $t7, $t8
li $t8, 0x15c815c8
beq $t7, $t8, nakamura2

move $t7, $zero
lbu $t8, 1($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 2($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 3($a0)
or $t7, $t7, $t8
sll $t7, $t7, 0x8
lbu $t8, 4($a0)
or $t7, $t7, $t8
li $t8, 0x08ae08ae
beq $t7, $t8, money

beq $t7, $t7, normal
onizka:
addiu $t5, $t5, 0x1
katagiri:
addiu $t5, $t5, 0x1
nakamura:
addiu $t5, $t5, 0x1
kanjaki:
addiu $t5, $t5, 0x1
onizka2:
addiu $t5, $t5, 0x1
katagiri2:
addiu $t5, $t5, 0x1
nakamura2:
addiu $t5, $t5, 0x1
money:
addiu $t5, $t5, 0x1
normal:
sw $t5, ''' + hex(ELF_BASE + newcode_baseaddr - 0x8) + '''
jr $ra
'''
code, _ = ks.asm(asm)
code_all += b"".join(map(p8, code)).ljust(0x500, b"\x00")

sceFontGetCharGlyphImage_Clip = 0xF7010
asm = '''
li $t7, 0xBDC1
bne $t7, $a1, not_whitespace
move $a1, $zero
not_whitespace:
j ''' + hex(ELF_BASE + sceFontGetCharGlyphImage_Clip) + '''
'''
code, _ = ks.asm(asm)
code_all += b"".join(map(p8, code)).ljust(0x500, b"\x00")
code_all += b"".join(map(p8, code)).ljust(0x500, b"\x00")

font_data_addr = newcode_baseaddr + 0x10000 - 0x4
font_size = len(open("AsiaKAMJB-SONY.pgf", "rb").read())
sceFontOpenUserMemory = 0xF7008
asm = '''
lw $v0, ''' + hex(ELF_BASE + font_data_addr) + '''
beq $v0, $zero, is_first_load
move $a1, $v0
li $a2, ''' + hex(font_size) + '''
is_first_load:
sw $a1, ''' + hex(ELF_BASE + font_data_addr) + '''
j ''' + hex(ELF_BASE + sceFontOpenUserMemory) + '''
'''
code, _ = ks.asm(asm)
code_all += b"".join(map(p8, code)).ljust(0x500, b"\x00")

asm = '''
lw $t7, 0($a2)
li $t8, 0x77777777
bne $t7, $t8, normal
lw $t7, 4($a2)
move $a2, $t7
normal:
j ''' + hex(ELF_BASE + 0xE1B00) + '''
'''
code, _ = ks.asm(asm)
code_all += b"".join(map(p8, code)).ljust(0x500, b"\x00")

data += code_all.ljust(0x10000, b"\x00")

patch_addr = [0x27A18, 0x279E4, 0x264A0, 0x26518, 0x23CD0, 0x20FF4]
for i in range(len(patch_addr)):
    code, _ = ks.asm("jal " + hex(newcode_baseaddr + (0x500 * i)), patch_addr[i])
    data = patch(data, TEXTSECTION_BASE + patch_addr[i], b"".join(map(p8, code))[:4])

bin_text = ["타이틀로뷁돌아가시겠습니까?", "예", "아니오", "성과:", "내용:", "평가:"]
bin_text_offset = [0x1314A4, 0x1314F8, 0x131500, 0x1314E0, 0x1314EC, 0x1314C8]
for i in range(len(bin_text)):
    data = patch(data, bin_text_offset[i], p8(0xC0 + len(bin_text[i])) + bin_text[i].encode("utf-16le") + b"\x00")

boot_bin = data

base_dir = "NPJG-90040/PSP_GAME/USRDIR/pack/"
pack_files = ["ep07_101.dat", "ep07_102.dat", "ep07_103.dat", "ep07_110.dat"]
hyb_files = ["ep07_101.hyb", "ep07_102.hyb", "ep07_103.hyb", "ep07_110.hyb"]
packs = [ PACK(base_dir + name) for name in pack_files ]
start_end = [(0x1C, 0x1E62), (0x1C, 0x1A47), (0x1C, 0x1649), (0x59, 0x545)]
text = []
for i in range(len(packs)):
    start, end = start_end[i]
    data = packs[i].unpack(hyb_files[i])

    ptr = start
    t = []
    while True:
        end_ptr = data.find(b"\x00", ptr)
        t.append( (ptr, data[ptr:end_ptr].decode("utf-8")) )
        if end_ptr == end: break
        ptr = end_ptr+1
    text.append(t)

arr = codecs.open(u"translated_text.txt", "r", "UTF-16").read().split("\n")
arridx = 0
for i in range(len(packs)):
    data = packs[i].unpack(hyb_files[i])
    for j in range(len(text[i])):
        if len(text[i][j][1].strip(" \n")) > 0:
            if arr[arridx].split("\t")[1] != "":
                length = len(arr[arridx].split("\t")[0].encode("utf-8"))
                kor = arr[arridx].split("\t")[1].replace(" ", "뷁")
                if text[i][j][1] != text[i][j][1].lstrip(" \n"):
                    llen = len(text[i][j][1]) - len(text[i][j][1].lstrip( "\n"))
                    kor = text[i][j][1][:llen] + kor
                if text[i][j][1] != text[i][j][1].rstrip(" \n"):
                    rlen = len(text[i][j][1]) - len(text[i][j][1].rstrip( "\n"))
                    kor += text[i][j][1][-rlen:]
                kor = kor.replace("[줄바꿈]", "\n")

                ptr = text[i][j][0]
                kor_utf16 = kor.encode("utf-16le")
                if length < len(kor_utf16)+1:
                    arridx += 1
                    continue
                if len(kor) > 31:
                    arridx += 1
                    continue

                data = patch(data, ptr, p8(0xC0 + len(kor)) + kor_utf16 + b"\x00")
            arridx += 1
    arridx += 1
    addr = ELF_BASE + newcode_baseaddr + 0x10000 + (0x4000 * i)
    boot_bin += gzip.compress(data).ljust(0x4000, b"\x00")
    packs[i].pack(hyb_files[i], data, addr = addr)

static = PACK(base_dir + "static.dat")
title = PACK(base_dir + "title.dat")
dev_logo = PACK(base_dir + "dev_logo.dat")

static.pack("DfpHsGothicW5Src9_5.pgf", open("AsiaKAMJB-SONY.pgf", "rb").read())

gim2 = [(packs[0],"nego_start.gim2"), (packs[0],"nego_result.gim2"), (packs[1],"nego_start.gim2"), (packs[2],"nego_start.gim2"), (packs[0],"nego_pps_7_101.gim2"), (packs[1],"nego_pps_7_102.gim2"), (packs[2],"nego_pps_7_103.gim2"), (packs[0],"cha1_title.gim2"), (packs[1],"cha2_title.gim2"), (packs[2],"cha3_title.gim2"), (packs[2],"7_103_07.gim2"), (packs[3],"cut_title.gim2"), (packs[3],"cut_package.gim2"), (static,"menu.gim2"), (static,"manual.gim2"), (static,"ope_guide.gim2"), (title,"title.gim2"), (dev_logo,"dev_logo_t.gim2")]
for pk, name in gim2:
    g = GIM2(pk.unpack(name))
    for a in g.list():
        try:
            g.pack(a, open("img/" + name + "/" + a + ".gim", "rb").read())
        except:
            pass
    pk.pack(name, g.save())

static.save("NPJG-90040_kor/PSP_GAME/USRDIR/pack/static.dat")
title.save("NPJG-90040_kor/PSP_GAME/USRDIR/pack/title.dat")
dev_logo.save("NPJG-90040_kor/PSP_GAME/USRDIR/pack/dev_logo.dat")
for i in range(len(packs)):
    packs[i].save("NPJG-90040_kor/PSP_GAME/USRDIR/pack/" + pack_files[i])

open("NPJG-90040_kor/PSP_GAME/SYSDIR/EBOOT.BIN", "wb").write(boot_bin)

os.system("mkisofs -iso-level 4 -xa -A \"PSP GAME\" -V \"NPJG-90040\" -sysid \"PSP GAME\" -volset \"\" -p \"\" -publisher \"\" -o a.iso NPJG-90040_kor/")