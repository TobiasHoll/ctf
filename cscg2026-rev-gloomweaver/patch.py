#!/usr/bin/env python3
import argparse
import dataclasses
import pathlib
import struct
import subprocess
import re

@dataclasses.dataclass
class Section:
    index: int
    rva: int
    offset: int
    size: int

    def file_to_section_offset(self, fo: int) -> int:
        assert self.offset <= fo < self.offset + self.size
        return fo - self.offset

    def section_offset_to_file(self, so: int) -> int:
        assert 0 <= so < self.size
        return self.offset + so

    def rva_to_section_offset(self, rva: int) -> int:
        assert self.rva <= rva < self.rva + self.size
        return rva - self.rva

    def section_offset_to_rva(self, so: int) -> int:
        assert 0 <= so < self.size
        return self.rva + so

    def rva_to_file(self, rva: int) -> int:
        return self.section_offset_to_file(self.rva_to_section_offset(rva))

    def file_to_rva(self, fo: int) -> int:
        return self.section_offset_to_rva(self.file_to_section_offset(fo))

    def file_slice(self) -> slice:
        return slice(self.offset, self.offset + self.size)


def find_section(input_file: pathlib.Path, name: str, section_type: str = "PROGBITS") -> Section:
    for line in subprocess.run(["readelf", "-WS", str(input_file)], check=True, capture_output=True).stdout.decode().splitlines():
        if (sec := re.search(r"\[\s*(\d+)\]\s+" + re.escape(name) + r"\s+" + re.escape(section_type) + r"\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", line)):
            return Section(
                index = int(sec.group(1)),
                rva = int(sec.group(2), 16),
                offset = int(sec.group(3), 16),
                size = int(sec.group(4), 16),
            )
    raise KeyError(f"Section {name} not found")


# This is terrible but we're in a bit of a hurry so...
def patch(input_file: pathlib.Path, output_file: pathlib.Path, constants_file: pathlib.Path):
    raw_bytes = bytearray(input_file.read_bytes())

    # Where are the sections?
    got = find_section(input_file, ".got")
    text = find_section(input_file, ".text")
    fini = find_section(input_file, ".fini")
    rela = find_section(input_file, ".rela.dyn", "RELA")
    symver = find_section(input_file, ".gnu.version", "VERSYM")
    build = find_section(input_file, ".note.gnu.build-id", "NOTE")

    # Where are the program headers?
    e_phoff = e_shoff = e_phnum = e_shnum = None
    for line in subprocess.run(["readelf", "-Wh", "bin"], check=True, capture_output=True).stdout.decode().splitlines():
        if "Start of program headers" in line:
            e_phoff = int(line.split(":")[1].strip().split()[0])
        elif "Start of section headers" in line:
            e_shoff = int(line.split(":")[1].strip().split()[0])
        elif "Number of program headers" in line:
            e_phnum = int(line.split(":")[1].strip())
        elif "Number of section headers" in line:
            e_shnum = int(line.split(":")[1].strip())
    assert e_phoff is not None, "program headers not found"
    assert e_shoff is not None, "section headers not found"
    assert e_phnum is not None, "program headers not found"
    assert e_shnum is not None, "section headers not found"

    # Edit program headers
    fini_ok = rela_ok = 0
    fini_eoff = None
    for i in range(e_phnum):
        p = e_phoff + i * 0x38
        ty, flags, off, rva, rpa, fsz, msz, algn = phdr = struct.unpack("=IIQQQQQQ", raw_bytes[p:p+0x38])

        # Make .rela.dyn writable
        if ty == 1 and off <= rela.offset < rela.offset + rela.size <= off + fsz:
            rela_ok += 1
            raw_bytes[p + 4] = 6

        # Shrink .fini (segment)
        if ty == 1 and off <= fini.offset < fini.offset + fini.size <= off + fsz:
            fini_ok += 1
            fini_eoff = raw_bytes[fini.file_slice()].index(bytes.fromhex("48 83 c4 08 c3")) + 5
            fini_last = raw_bytes[fini.file_slice()].rindex(bytes.fromhex("48 83 c4 08 c3"))
            assert fini_last >= fini_eoff
            assert msz == fsz
            seg_size = fini_eoff + fini.offset - off

            raw_bytes[p + 32:p + 40] = raw_bytes[p + 40:p + 48] = struct.pack("=Q", seg_size)

            # Remove crtn.o trailer
            raw_bytes[fini.offset + fini_last:fini.offset + fini_last + 5] = b"\x00" * 5

            # Shrink .fini section
            s = e_shoff + fini.index * 0x40
            raw_bytes[s + 32:s + 40] = struct.pack("=Q", fini_eoff)

            # Make text writable
            raw_bytes[p + 4] = 7

    assert rela_ok == 1, "failed to patch .rela.dyn"
    assert fini_ok == 1, "failed to patch .fini"
    assert fini_eoff is not None, "failed to find hook"

    # Figure out the symbols
    weak_symbol = None
    libc_start_main_symbol = None
    for line in subprocess.run(["readelf", "-Ws", str(input_file)], check=True, capture_output=True).stdout.decode().splitlines():
        if "WEAK" in line and "crt0.o" in line:
            weak_symbol = int(line.split(":")[0].strip())
        if "__libc_start_main" in line:
            libc_start_main_symbol = int(line.split(":")[0].strip())
    assert weak_symbol is not None, "unresolvable weak symbol not found"
    assert libc_start_main_symbol is not None, "__libc_start_main symbol not found"

    # Version our symbol.
    weak_ver_offset = symver.offset + 2 * weak_symbol
    libc_start_main_ver_offset = symver.offset + 2 * libc_start_main_symbol
    raw_bytes[weak_ver_offset:weak_ver_offset + 2] = raw_bytes[libc_start_main_ver_offset:libc_start_main_ver_offset + 2]

    # Replace the fake GOT entry.
    fake_got_entry_offset = raw_bytes.index(b"(p: got)")
    fake_got_entry_rva = got.file_to_rva(fake_got_entry_offset)
    raw_bytes[fake_got_entry_offset : fake_got_entry_offset + 8] = b"\0" * 8

    # Figure out the GOT entries
    libc_start_main_got_entry = None
    for line in subprocess.run(["readelf", "-W", "--got-contents", str(input_file)], check=True, capture_output=True).stdout.decode().splitlines():
        if "__libc_start_main@" in line:
            libc_start_main_got_entry = int(line.split("R_X86_64_GLOB_DAT", 1)[0].split(":")[1].strip(), 16)
    assert libc_start_main_got_entry is not None, "__libc_start_main GOT entry not found"

    # Find the existing relocation, and the correct symbol
    libc_start_main_relocation = None
    for line in subprocess.run(["readelf", "-Wr", str(input_file)], check=True, capture_output=True).stdout.decode().splitlines():
        if "__libc_start_main@" in line:
            assert (r := re.match(r"^([0-9a-f]+)\s+([0-9a-f]+)\s+R_X86_64_GLOB_DAT\s+([0-9a-f]+)", line.strip())), f"bad line: {line}"
            assert libc_start_main_symbol == int(r.group(2), 16) >> 32
            libc_start_main_relocation = struct.pack("=QQQ", int(r.group(1), 16), int(r.group(2), 16), int(r.group(3), 16))
    assert libc_start_main_relocation is not None, "__libc_start_main relocation not found"

    # Copy the original __libc_start_main entry to the new fake GOT entry
    saved_relocation = struct.pack("=QIIQ", fake_got_entry_rva, 6, libc_start_main_symbol, 0)
    raw_bytes = raw_bytes.replace(b"(patch: fake relocation)", saved_relocation, 1)

    # Use that relocation in the actual .fini
    disp = fini.section_offset_to_file(raw_bytes[fini.file_slice()].index(bytes.fromhex("f4f4f44f")))
    disp_rip = fini.file_to_rva(disp) + 4 # rip is past the end of that.
    disp_new = struct.pack("i", fake_got_entry_rva - disp_rip)
    raw_bytes[disp : disp + 4] = disp_new

    # Add our cursed relocations
    iro = rela.file_to_rva(raw_bytes.index(b"(patch: fake relocation)") + 0x18)
    internal_relocation = struct.pack(
        "=QIIQ",
        iro, # Offset
        1, # Type
        weak_symbol, # Symbol
        libc_start_main_got_entry, # Addend
    )
    real_relocation = struct.pack(
        "=QIIQ",
        0, # Offset
        8, # Type
        0, # Symbol
        fini.section_offset_to_file(fini_eoff), # Addend
    )
    raw_bytes = raw_bytes.replace(b"(patch: fake relocation)", internal_relocation, 1)
    raw_bytes = raw_bytes.replace(b"(patch: fake relocation)", real_relocation, 1)
    raw_bytes = raw_bytes.replace(b"(patch: fake relocation)", b"\x00" * 24)

    # Edit in our constants
    constants = {}
    for line in subprocess.run(["objdump", "-t", str(constants_file)], check=True, capture_output=True).stdout.decode().splitlines():
        line = line.strip()
        if ".rodata" not in line or "s1_" not in line:
            continue
        address, *_, symbol = line.split()
        constants[symbol] = int(address, 16)

    deltas = ["s1_coeffs", "s1_offset_u", "s1_offset_v", "s1_result"]
    for i, symbol in enumerate(deltas):
        marker = (0x4fccf400 | i).to_bytes(4, "little")
        found = raw_bytes.count(marker)
        assert found == 2, f"Marker {marker:#x} for {symbol} found {found} times"
        actual_delta = constants[symbol] - constants[symbol + "_fake"]
        raw_bytes = raw_bytes.replace(marker, actual_delta.to_bytes(4, "little", signed=True))
            
    output_file.write_bytes(raw_bytes)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", help="ELF file to process", type=pathlib.Path)
    parser.add_argument("constants_file", help="Object file with constants", type=pathlib.Path)
    parser.add_argument("output_file", help="Output file (default: same as input file)", type=pathlib.Path, nargs="?")
    args = parser.parse_args()

    patch(args.input_file, args.output_file or args.input_file, args.constants_file)
