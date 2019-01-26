from elftools.elf.elffile import ELFFile
from sys import argv

file_handle = open(argv[1], 'rb')

elf = ELFFile(file_handle)
sections = list(elf.iter_sections())

for i, section in enumerate(sections):
    print(f'LOAD {i:2} {section["sh_flags"] & 0xFF:03b} {section["sh_addr"]:08X} {section["sh_addr"] + section.data_size:08X} {section.name}')

file_handle.close()
