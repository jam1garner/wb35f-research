with open('elf_magics_found.csv') as f:
    locations = [int(line.rstrip('\n'), 16) for line in f.readlines()]

with open('WB35F_DSC_UP_8500.elf', 'rb') as f:
    for i, loc in enumerate(locations):
        f.seek(loc)
        if i == len(locations) - 1:
            # if final offset
            data = f.read()
        else:
            data = f.read(locations[i+1] - loc)
        with open(f'elfs/firm_{i}.elf', 'wb') as elf:
            elf.write(data)