from elftools.elf.elffile import ELFFile
from binascii import hexlify

from unicorn import *
from unicorn.mips_const import *

import struct
import re

global instructions_run
instructions_run = 0
# 0 = log everything
# 1 = log debug prints and hardware access
# 2 = log debug prints
QUIET_LEVEL = 2

def load_symbols():
    global symbols
    with open('elf_symbol_map.csv', 'r') as f:
        csv = [line.rstrip().split(',') for line in f.readlines()]
    symbols = []
    for line in csv:
        symbols.append((int(line[0], 0x10), line[1]))

def get_symbol(addr):
    global symbols
    # Just to speed stuff up, this is a good quick check
    if addr & 0x80000000 == 0:
        return None
    # If not in kernel range 
    if not addr in range(0x80010000, 0x8008E178):
        return None

    for i in range(len(symbols)):
        if symbols[i][0] > addr:
            return symbols[i-1]

def get_string(addr):
    s = ""
    c = uc.mem_read(addr, 1)
    while c != b'\x00':
        s += c.decode('latin8')
        addr += 1
        c = uc.mem_read(addr, 1)
    return s

def hook_code(uc, address, size, user_data):
    global instructions_run
    instructions_run += 1
    pc = uc.reg_read(UC_MIPS_REG_PC)
    #print(f"PC - {pc:08X}")
    #if pc in range(0x8002D130, 0x8002D194):
    #    print("---------------")
    #    dump_regs(uc)
    if pc == 0x8002D194: # Infinite loop from bad PRId, hacky fix
        uc.reg_write(UC_MIPS_REG_T4, 0x1)
    if pc == 0x8002A9C4: # OsSysHaltEx
        error = get_string(uc.reg_read(UC_MIPS_REG_A0))
        filename = get_string(uc.reg_read(UC_MIPS_REG_A1))
        print(f"\nOsSysHaltEx in {filename}: {error}")
    return True

def dump_regs(uc):
    zr = uc.reg_read(UC_MIPS_REG_ZERO)
    at = uc.reg_read(UC_MIPS_REG_AT)
    v0 = uc.reg_read(UC_MIPS_REG_V0)
    v1 = uc.reg_read(UC_MIPS_REG_V1)
    a0 = uc.reg_read(UC_MIPS_REG_A0)
    a1 = uc.reg_read(UC_MIPS_REG_A1)
    a2 = uc.reg_read(UC_MIPS_REG_A2)
    a3 = uc.reg_read(UC_MIPS_REG_A3)
    t0 = uc.reg_read(UC_MIPS_REG_T0)
    t1 = uc.reg_read(UC_MIPS_REG_T1)
    t2 = uc.reg_read(UC_MIPS_REG_T2)
    t3 = uc.reg_read(UC_MIPS_REG_T3)
    t4 = uc.reg_read(UC_MIPS_REG_T4)
    t5 = uc.reg_read(UC_MIPS_REG_T5)
    t6 = uc.reg_read(UC_MIPS_REG_T6)
    t7 = uc.reg_read(UC_MIPS_REG_T7)
    s0 = uc.reg_read(UC_MIPS_REG_S0)
    s1 = uc.reg_read(UC_MIPS_REG_S1)
    s2 = uc.reg_read(UC_MIPS_REG_S2)
    s3 = uc.reg_read(UC_MIPS_REG_S3)
    s4 = uc.reg_read(UC_MIPS_REG_S4)
    s5 = uc.reg_read(UC_MIPS_REG_S5)
    s6 = uc.reg_read(UC_MIPS_REG_S6)
    s7 = uc.reg_read(UC_MIPS_REG_S7)
    gp = uc.reg_read(UC_MIPS_REG_GP)
    sp = uc.reg_read(UC_MIPS_REG_SP)
    pc = uc.reg_read(UC_MIPS_REG_PC)
    ra = uc.reg_read(UC_MIPS_REG_RA)
    fp = uc.reg_read(UC_MIPS_REG_FP)
    pcComment = ""
    symbol = get_symbol(pc)
    if symbol != None:
        offset = pc - symbol[0]
        pcComment = f" ({symbol[1]}{'+' + hex(offset) if offset != 0 else ''})"
    raComment = ""
    symbol = get_symbol(ra)
    if symbol != None:
        offset = ra - symbol[0]
        raComment = f" ({symbol[1]}{'+' + hex(offset) if offset != 0 else ''})"
    print("\nRegs")
    print(f"sp {sp:08X} pc {pc:08X}{pcComment}")
    print(f"v0 {v0:08X} v1 {v1:08X} ra {ra:08X}{raComment}")
    print(f"t0 {t0:08X} t1 {t1:08X} t2 {t2:08X} t3 {t3:08X}")
    print(f"t4 {t4:08X} t5 {t5:08X} t6 {t6:08X} t7 {t7:08X}")
    print(f"s0 {s0:08X} s1 {s1:08X} s2 {s2:08X} s3 {s3:08X}")
    print(f"s4 {s4:08X} s5 {s5:08X} s6 {s6:08X} s7 {s7:08X}")
    print(f"a0 {a0:08X} a1 {a1:08X} a2 {a2:08X} a3 {a3:08X}")

def dump_stack(uc):
    sp = uc.reg_read(UC_MIPS_REG_SP)
    print("\nStack")
    for addr in range(sp, sp + 0x50, 0x4):
        comment = ""
        value = struct.unpack('<L', uc.mem_read(addr, 0x4))[0]
        symbol = get_symbol(value)
        if symbol != None:
            offset = value - symbol[0]
            comment = f" | {symbol[1]}{'+' + hex(offset) if offset != 0 else ''}"
        print(f"{addr:08X}: {value:08X}{comment}")

print("FILELOAD firm_0_COACH_kern.elf")
file_handle = open('./firm_0_COACH_kern.elf', 'rb')

elf = ELFFile(file_handle)
sections = list(elf.iter_sections())

entry = elf['e_entry']

uc = Uc(UC_ARCH_MIPS, UC_MODE_32)

# Needed memory mappings
# 80000180 - 8009FCB8 | r-x | .exception through .spc0.972___COUNTER__
# 8009FCB8 - 800CA4C8 | rw- | .eh_frame through .bss
# 90008000 - 90009C00 | -w- | .spd0 through .spd4
# BFC08000 - BFC09C00 | rwx | .spc0 through .spc4

# Needed hardware mappings
# 0xb0400840 | some sort of LED?

uc.mem_map(0x80000000, 0xD0000) # We have to map r-x and rw- together because unicorn :(
uc.mem_map(0x90000000, 0xA000)
uc.mem_map(0xBFC00000, 0xA000)

# Map peripherials(?)
PERIPHERIAL_LIST = [
    ("unk_1", (0xB0400000, 0x1000)), # 0xB0400840 is written to at the beginning
    ("unk_2", (0xB0801000, 0x1000)), # 0xB0801034 is written in CpuInit
    ("unk_3", (0xB0802000, 0x1000)), # fake read from B0802040
    ("unk_4", (0xB0800000, 0x1000)), # 0xB08002C8
    ("dcu",   (0xB8000000, 0x3000)), # 0xB800207C is DRAM Controller attr 1, 0xB8002198 is attr 0
    ("unk_5", (0x807FF000, 0x1000)), # 0x807FFF98 is used for somemthing idk
    #("unk_6", (0x8044C000, 0x1000)), # gonna keep mapping memory till something breaks (0x8044C644)
    #("unk_7", (0x805CF000, 0x1000)),
    #("unk_8", (0x8044D000, 0x3000)),
]

def hook_mem_write(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_MIPS_REG_PC)
    for p in PERIPHERIAL_LIST:
        if address in range(p[1][0], p[1][0] + p[1][1]):
            if QUIET_LEVEL < 3:
                print(f"WRITE {value:08X} at {address:08X} ({size} bytes)  PC:{pc:08X} | PERIPHERIAL {p[0]}")
            return True
    if QUIET_LEVEL < 2:
        print(f"WRITE {value:08X} at {address:08X} ({size} bytes)  PC:{pc:08X}")
    return True

def hook_mem_write_unmapped(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_MIPS_REG_PC)
    print(f"WRITE UNMAPPED {value:08X} at {address:08X} ({size} bytes)  PC:{pc:08X}")
    return True

def hook_mem_read(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_MIPS_REG_PC)
    for p in PERIPHERIAL_LIST:
        if address in range(p[1][0], p[1][0] + p[1][1]):
            if QUIET_LEVEL < 3:
                print(f"READ at {address:08X} ({size} bytes)  PC:{pc:08X} | PERIPHERIAL {p[0]}")
            return True
    if QUIET_LEVEL < 2:
        print(f"READ at {address:08X} ({size} bytes)  PC:{pc:08X}")
    return True

def hook_mem_read_unmapped(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_MIPS_REG_PC)
    print(f"READ UNMAPPED {value:08X} at {address:08X} ({size} bytes)  PC:{pc:08X}")
    return True

for peripherial in PERIPHERIAL_LIST:
    mapping = peripherial[1]
    uc.mem_map(mapping[0], mapping[1])

for i, section in enumerate(sections):
    if section["sh_addr"] == 0:
        continue
    print(f'LOAD {i:2} {section["sh_flags"] & 0xFF:03b} {section["sh_addr"]:08X} {section["sh_addr"] + section.data_size:08X} {section.name}')
    uc.mem_write(section["sh_addr"], section.data())

load_symbols()
print("SYMBOLS LOADED")

def empty_func(a,b,c,d):
    pass
# Map HOOK_CODE to an empty function, which fixes the fact unicorn's
# reg read's PC value doesn't update after the first jal cause reasons???
uc.hook_add(UC_HOOK_CODE, hook_code)

uc.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_write_unmapped)
uc.hook_add(UC_HOOK_MEM_READ, hook_mem_read)
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_read_unmapped)

print(f'JUMP Entrypoint: {entry:08X}')
try:
    uc.emu_start(entry, 0x8009F6CC)
except unicorn.UcError as e:
    print(f"ERROR: {e}")
dump_regs(uc)
dump_stack(uc)
print(f"Ran {instructions_run} instructions")
file_handle.close()
