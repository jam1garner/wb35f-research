from elftools.elf.elffile import ELFFile
from binascii import hexlify

from unicorn import *
from unicorn.mips_const import *

import math
def roundup(x):
    return int(math.ceil(x / 2048.0)) * 2048

def hook_code(uc, address, size, user_data):
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
    print(f"PC - {pc:08X}")
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
    print(f"v0 {v0:08X} v1 {v1:08X}")
    print(f"pc {pc:08X} sp {sp:08X}")

def hook_mem_write(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_MIPS_REG_PC)
    print(f"WRITE {value} at {hex(address)} ({size} bytes)  PC:{hex(pc)}")
    return True

file_handle = open('./firm_0_COACH_kern.elf', 'rb')

elf = ELFFile(file_handle)
sections = list(elf.iter_sections())

entry = elf['e_entry']

uc = Uc(UC_ARCH_MIPS, UC_MODE_32)

# Needed mappings
# 80000180 - 8009FCB8 | r-x | .exception through .spc0.972___COUNTER__
# 8009FCB8 - 800CA4C8 | rw- | .eh_frame through .bss
# 90008000 - 90009C00 | -w- | .spd0 through .spd4
# BFC08000 - BFC09C00 | rwx | .spc0 through .spc4

uc.mem_map(0x80000000, 0xD0000) # We have to map r-x and rw- together because unicorn :(
uc.mem_map(0x90000000, 0xA000)
uc.mem_map(0xBFC00000, 0xA000)

for i, section in enumerate(sections):
    if section["sh_addr"] == 0:
        continue
    print(f'LOAD {i:2} {section["sh_flags"] & 0xFF:03b} {section["sh_addr"]:08X} {section["sh_addr"] + section.data_size:08X} {section.name}')
    uc.mem_write(section["sh_addr"], section.data())
#    if not section.name in [".text", ".bss", ".data"]:
#        continue
#    print(section.data_size)
#    print(f'LOAD {i:2} {section["sh_flags"] & 0xFF:08b} {section["sh_addr"]:08X} {section.name}')
#    mu.mem_map(section["sh_addr"], roundup(section.data_size))

def empty_func(a,b,c,d):
    pass

uc.hook_add(UC_HOOK_CODE, empty_func)
uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_write)

print(f'JUMP Entrypoint: {entry:08X}')
try:
    uc.emu_start(entry, 0x8009F6CC)
except unicorn.UcError as e:
    print(f"ERROR: {e}")
    dump_regs(uc)
file_handle.close()
