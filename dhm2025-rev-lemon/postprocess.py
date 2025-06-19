#!/usr/bin/env python3

# We have to post-process the generated code to remove the GOT lookups via `call/pop`.
# Those only work if %cs/%ds are the same. Luckily, we need a place to put our fake
# %ds setup anyways - for now, we've just inserted a nopl that we can find again.
# (These are inserted somewhere deep down in codegen, and we don't want YET ANOTHER PLUGIN
# to try and deal with those). Also, we want to randomize the relocations.
# We would also want to randomize the relocation symbols - but that's already dealt with by
# turning them into ELF-relative relocations.

import argparse
import dataclasses
import itertools
import hashlib
import pathlib
import random
import re
import struct

from capstone.x86_const import *
from capstone import *

dis = Cs(CS_ARCH_X86, CS_MODE_32)
dis.detail = True

parser = argparse.ArgumentParser()
parser.add_argument('elf', help='Binary to post-process', type=pathlib.Path)
parser.add_argument('-s', '--seed', help='Random seed')
parser.add_argument('-n', '--dry-run', help='Do not modify the binary', action='store_true')
args = parser.parse_args()

elf = bytearray(args.elf.read_bytes())


@dataclasses.dataclass
class Section:
    name: str
    addr: int
    offset: int
    size: int
    index: int
    @property
    def end_addr(self) -> int:
        return self.addr + self.size
    @property
    def end_offset(self) -> int:
        return self.offset + self.size

sections = {}

e_shoff = int.from_bytes(elf[0x20:0x24], 'little')
e_shnum = int.from_bytes(elf[0x30:0x32], 'little')
e_shstrndx = int.from_bytes(elf[0x32:0x34], 'little')

raw_sections = []
for shndx in range(e_shnum):
    sh = elf[e_shoff + shndx * 0x28:e_shoff + shndx * 0x28 + 0x28]
    sh_name = int.from_bytes(sh[0x00:0x04], 'little')
    sh_addr = int.from_bytes(sh[0x0c:0x10], 'little')
    sh_offset = int.from_bytes(sh[0x10:0x14], 'little')
    sh_size = int.from_bytes(sh[0x14:0x18], 'little')
    raw_sections.append((sh_name, sh_addr, sh_offset, sh_size))

shstrtab = elf[raw_sections[e_shstrndx][2]:]
for index, (sh_name, sh_addr, sh_offset, sh_size) in enumerate(raw_sections):
    if not index:
        continue
    name = shstrtab[sh_name:]
    name = name[:name.find(b'\0')]
    s_name = name.decode(errors='replace')
    sections[s_name] = Section(s_name, sh_addr, sh_offset, sh_size, index)

descriptors = {
    int.from_bytes(elf[off:off+4], 'little'): off
    for off in range(sections['.lemonade.descriptors'].offset, sections['.lemonade.descriptors'].end_offset, 0x10)
}

random.seed(args.seed if args.seed is not None else hashlib.sha256(elf).digest())

symtab = elf[sections['.symtab'].offset:sections['.symtab'].end_offset]
strtab = elf[sections['.strtab'].offset:sections['.strtab'].end_offset]

@dataclasses.dataclass
class Symbol:
    name: str
    section: Section | None
    value: int
    size: int
    @property
    def end(self) -> int:
        return self.value + self.size
    @property
    def offset(self) -> int:
        assert self.section
        return self.value + self.section.offset - self.section.addr
    @property
    def end_offset(self) -> int:
        assert self.section
        return self.end + self.section.offset - self.section.addr

sections_by_index = { s.index: s for s in sections.values() }
symbols = {}

for sym in itertools.batched(symtab, 16, strict=True):
    st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack('IIIBBH', bytes(sym))
    name = strtab[st_name:]
    name = name[:name.find(b'\0')].decode(errors='replace')
    symbols[name] = Symbol(name, sections_by_index.get(st_shndx), st_value, st_size)

base_names = set(s.name.split('.', 1)[0] for s in symbols.values() if 'lemonade' in s.name)
padding = None
thunk_adjustment = None
targets = []

for s in symbols.values():
    if not s.section or '.text' not in s.section.name:
        continue
    if 'lemonade' not in s.name and not s.name in base_names:
        continue
    if s.name in base_names:
        targets.insert(0, s)
    else:
        targets.append(s)

for s in targets:
    print(f'\x1b[34m{s.name}\x1b[0m')
    stack_adjustment = 0
    adjustments = []
    got_register = None
    selector = None

    stack_relative = set()
    stack_memory = set()

    stack_adjustment_addr = None
    call_pop_range = None
    nop_hlt_range = None
    prologue_range = None
    is_prologue = True

    return_thunk_add = None
    return_thunk_save = None
    is_main = False
    is_thunk = False
    is_stub = False

    jumps = {}
    calls = {}

    prev = next(dis.disasm(b'\xc3', 0, 1))
    for insn in dis.disasm(elf[s.offset:s.end_offset], s.offset):
        print(s.name, hex(insn.address - sections['.text'].offset + sections['.text'].addr), insn)
        if insn.id == X86_INS_JMP and insn.address == s.offset and insn.address + len(insn.bytes) == s.end_offset: # stub:
            is_stub = True
        if is_prologue and insn.id == X86_INS_SUB and insn.operands[0].type == X86_OP_REG and insn.operands[0].reg == X86_REG_ESP and insn.operands[1].type == X86_OP_IMM:
            stack_adjustment += insn.operands[1].imm
            adjustments.append((X86_INS_SUB, insn.operands[1].imm))
        elif is_prologue and insn.id == X86_INS_PUSH:
            assert insn.operands[0].type == X86_OP_REG
            assert str(dis.reg_name(insn.operands[0].reg)).startswith('e')
            assert len(insn.bytes) == 1
            stack_adjustment += 4
            reg = insn.bytes[0] & 7
            adjustments.append((X86_INS_PUSH, reg))
        elif is_prologue:
            is_prologue = False
            prologue_range = (s.offset, insn.address)
        if insn.id == X86_INS_POP and prev.id == X86_INS_CALL and prev.operands[0].imm == insn.address:
            call_pop_range = (prev.address, insn.address + len(insn.bytes))
            assert len(insn.bytes) == 1
            got_register = insn.bytes[0] & 7 # insn.operands[0].reg, but immediately usable for reassembly
        elif insn.id == X86_INS_POP and not prev.id == X86_INS_PUSH and prologue_range and not prev.address in range(*prologue_range):
            raise RuntimeError('unexpected pop, may have killed corresponding push earlier')
        if insn.id == X86_INS_NOP:
            if len(insn.operands) > 0 and insn.operands[0].type == X86_OP_MEM and insn.operands[0].mem.base == X86_REG_ESP:
                selector = -insn.operands[0].mem.disp
                assert selector & 7 in (3, 7) # 3 only in the no-randomize case!
            if insn.bytes != b'\x90':
                nop_hlt_range = (insn.address, None)
        if prev.id == X86_INS_HLT and insn.id != X86_INS_HLT:
            assert nop_hlt_range is not None and nop_hlt_range[1] is None
            nop_hlt_range = (nop_hlt_range[0], insn.address)
        if insn.group(X86_GRP_JUMP) and not insn.bytes.startswith(b'\xff'):
            assert insn.operands[0].type == X86_OP_IMM
            jumps[insn.address] = (insn.bytes, insn.operands[0].imm) # Raw bytes of this type of jump are never modified below
        if insn.id == X86_INS_CALL:
            assert insn.bytes.startswith(b'\xe8')
            if insn.bytes != b'\xe8\x00\x00\x00\x00':
                assert not (s.offset <= insn.operands[0].imm < s.end_offset)
                calls[insn.address] = (insn.bytes, insn.operands[0].imm)
        if prev.id == X86_INS_ADD and prev.operands[0].type == X86_OP_MEM and prev.operands[0].mem.base == X86_REG_ESP and prev.operands[1].type == X86_OP_IMM \
           and prev.operands[1].imm == 42 and insn.id == X86_INS_RETF:
            return_thunk_add = prev.address
        if prev.id == insn.id == X86_INS_PUSH and prev.operands[0].type == insn.operands[0].type == X86_OP_REG and prev.operands[0].reg == X86_REG_CS \
           and insn.operands[0].reg == X86_REG_DS:
            is_main = True
        if insn.id == X86_INS_MOV and insn.operands[1].type == X86_OP_REG and insn.operands[1].reg == X86_REG_ESP:
            assert insn.operands[0].type == X86_OP_MEM
            assert is_main
            assert not return_thunk_save
            return_thunk_save = insn.address
        if insn.id == X86_INS_RETF:
            is_thunk = True
        for oi, op in enumerate(insn.operands):
            # if op.type == X86_OP_REG and op.reg == X86_REG_ESP or \
            #    op.type == X86_OP_MEM and op.mem.base in (X86_REG_ESP, X86_REG_EBP):
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_ESP:
                stack_relative.add(insn.address)
                stack_memory.add(insn.address)
        prev = insn

    if is_stub:
        continue

    assert got_register is not None
    assert nop_hlt_range is not None and nop_hlt_range[1] is not None

    replacement = b''
    mapping = {}
    got_setup = False
    for insn in dis.disasm(elf[s.offset:s.end_offset], s.offset):
        if insn.address in range(*nop_hlt_range):
            continue
        if selector is not None:
            if prologue_range and insn.address in range(*prologue_range):
                continue
            assert return_thunk_save is None
            if call_pop_range and insn.address in range(*call_pop_range):
                if got_setup:
                    continue
                got_setup = True
                desc_addr = descriptors[selector // 8]
                base = int.from_bytes(elf[desc_addr + 4:desc_addr + 8], 'little', signed=True)

                if base == 0:
                    print('\x1b[1;33mUsing default %ds without randomization, keeping call/pop\x1b[0m')
                    assert len(replacement) <= insn.address - s.offset
                    while len(replacement) < insn.address - s.offset:
                        replacement += b'\x90'
                    replacement += b'\xe8\x00\x00\x00\x00'
                    replacement += bytes([0x58 | got_register])
                    continue
                # Step 1: Replace
                #   e8 00 00 00 00    call $+5
                #   5?                popl %...
                #   0f 1f ?4 24 ..    nopl ...
                # with
                #   66 6? ..          pushw $sel
                #   66 1f             popw %ds
                #   b? ..             movl $off, %...
                # Normally, we end up with call_target (%ds-relative) in %got_register
                # We want to achieve the same thing.
                # This is relative to the ELF start, thanks to Rel (not Rela) relocations.
                call_target = (call_pop_range[0] + 5) - sections['.text'].offset + sections['.text'].addr
                offset = call_target - base
                if selector > 0x7f:
                    replacement += b'\x66\x68' + selector.to_bytes(2, 'little')
                else:
                    replacement += b'\x66\x6a' + selector.to_bytes(1, 'little')
                replacement += b'\x66\x1f'
                replacement += (0xb8 + got_register).to_bytes(1, 'little') + offset.to_bytes(4, 'little')
                continue
        elif is_main:
            assert selector is None
            thunk_adjustment = adjustments

        mapping[insn.address] = s.offset + len(replacement)
        output = insn.bytes
        if insn.address in stack_relative:
            output = b'\x36' + output
        if insn.address == return_thunk_add:
            offset = len(replacement) + len(output) + 1 # lret (cb)
            assert 0 <= offset < 0x80
            output = output.replace(b'\x2a', offset.to_bytes(1, 'little'))
        elif stack_adjustment and insn.address in stack_memory:
            op = next(op for op in insn.operands if op.type == X86_OP_MEM and op.mem.base == X86_REG_ESP)
            new_disp = op.mem.disp - stack_adjustment
            # Hacky, but beats bringing in keystone also
            if op.mem.disp == 0:
                if insn.id == X86_INS_MOV and insn.bytes[0] == 0xc7:
                    index = output.find(b'\x24')
                else:
                    index = -1
                assert output[index] == 0x24 and (output[index - 1] & 0xc0) == 0, insn
                assert -0x80 <= new_disp < 0x80, insn
                output = output[:index - 1] + bytes([output[index - 1] | 0x40, 0x24]) + new_disp.to_bytes(1, 'little', signed=True) + (output[index + 1:] if index > 0 else b'')
            else:
                assert -0x80 <= new_disp < op.mem.disp < 0x80
                modrm = output.find(b'\x24', 1)
                assert modrm > 0
                index = output.find(op.mem.disp.to_bytes(1, signed=True), modrm)
                assert index > 0, insn
                output = output[:index] + new_disp.to_bytes(1, 'little', signed=True) + output[index + 1:]

        if is_thunk and insn.id == X86_INS_RETF and thunk_adjustment:
            for op, arg in thunk_adjustment[::-1]:
                if op == X86_INS_SUB:
                    output += b'\x83\xc4' + arg.to_bytes(1, 'little')
                elif op == X86_INS_PUSH:
                    output += (0x58 | arg).to_bytes(1, 'little')
                else:
                    raise ValueError('unknown stack adjustment')
            thunk_adjustment = None

        replacement += output

    replacement = bytearray(replacement)
    for source, (raw, destination) in jumps.items():
        new_source = mapping[source]
        new_destination = mapping[destination]
        jump_by = new_destination - (new_source + len(raw))
        index = new_source - s.offset
        assert replacement[index:index + len(raw)] == raw
        replacement[index:index + len(raw)] = raw[:1] + jump_by.to_bytes(len(raw) - 1, 'little')

    for source, (raw, destination) in calls.items():
        new_source = mapping[source]
        jump_by = destination - (new_source + len(raw))
        index = new_source - s.offset
        assert len(raw) == 5
        replacement[index:index + len(raw)] = raw[:1] + jump_by.to_bytes(len(raw) - 1, 'little')

    space = s.end_offset - s.offset
    if padding is None:
        padding = b'\xcc' if elf[s.end_offset] == 0xcc else \
                  b'\x90' if elf[s.end_offset] in (0x90, 0x0f) else \
                  None
    replacement = replacement.ljust(space, padding or b'\x90')
    assert len(replacement) == space
    elf[s.offset:s.end_offset] = replacement

    print('\x1b[32m', end='')
    for insn in dis.disasm(elf[s.offset:s.end_offset], s.offset):
        print(s.name, hex(insn.address - sections['.text'].offset + sections['.text'].addr), insn)
    print('\x1b[0m')

assert thunk_adjustment is None, 'Fix the order please'

# Finally, restore breakpoints to make them work in GDB.
text = slice(sections['.text'].offset, sections['.text'].end_offset)
elf[text] = elf[text].replace(b'\xcd\x03' * 3, b'\xcc'.ljust(6, b'\x90'))

if not args.dry_run:
    args.elf.write_bytes(elf)

exit(0)
