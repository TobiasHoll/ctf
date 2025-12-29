import argparse
import functools
import operator
import pathlib
import pwn
import re
import struct
import subprocess
import tempfile
import z3

from Crypto.Cipher import AES

if __name__ != '__main__':
    raise ImportError('Don\'t import this, please')

parser = argparse.ArgumentParser()
parser.add_argument('binary', help='chekhov binary', type=pathlib.Path, default=pathlib.Path('./chekhov'))
args = parser.parse_args()

pwn.context.arch = 'amd64'

readelf = subprocess.run(['readelf', '-l', str(args.binary)], check=True, capture_output=True)
load = None
for line in readelf.stdout.decode().splitlines():
    parts = { index: segment for index, segment in enumerate(line.strip().split()) }
    if parts.get(0) == 'LOAD':
        try:
            load = (int(parts.get(1, '<invalid>'), 0), int(parts.get(2, '<invalid>'), 0))
        except ValueError:
            pass
        continue
    elif load is not None:
        if parts[2] == 'R' and parts[3] == 'E':
            # Text segment
            text_offset = load[0]
            text_rva = load[1]
            text_file_size = int(parts.get(0, '<invalid>'), 0)
            break
else:
    raise ValueError('Failed to find text segment in file')
text_delta = text_rva - text_offset

elf = args.binary.read_bytes()

readelf = subprocess.run(['readelf', '-r', str(args.binary)], check=True, capture_output=True)
lines = readelf.stdout.decode().split('\n')
start = next(index for index, line in enumerate(lines) if '.rela.dyn' in line) + 2
end = next(index for index, line in enumerate(lines) if index > start and not line.strip())
relative = (line.split() for line in lines[start:end] if 'R_X86_64_RELATIVE' in line)
values = ((e[0], e[3]) for e in relative)
relocs = { int(addr, 16): int(value, 16) for addr, value in values }

reloc_base = next(b for b in sorted(relocs.keys()) if re.match(
    b'\x48\xb8.{8}\x48\xb9.{8}\xc4\xe1\xf9\x6e\xc0',
    elf[relocs[b] - text_delta:relocs[b] - text_delta + 0x20]
))

# Patch the binary to extract the list of checks
constant = elf.index((0x0c028aa03).to_bytes(4, 'little'))
ioctl = elf.index(b'\x0f\x05', constant)

first_check_rva = min(relocs[reloc_base + check_id * 8] for check_id in range(1024))
last_check_rva = max(relocs[reloc_base + check_id * 8] for check_id in range(1024))

tail_code = pwn.disasm(elf[last_check_rva - text_delta:text_offset + text_file_size], last_check_rva)

aeskeygenassist_rva = next(int(line.strip().split(':')[0], 16) for line in tail_code.split('\n')
                       if 'aeskeygenassist' in line)

lines = [line.strip() for line in pwn.disasm(elf[ioctl:ioctl + 8], ioctl + text_delta).split('\n')]
assert len(lines) == 2
assert re.match('^[0-9a-f]+: +0f 05 +syscall$', lines[0]) is not None
assert re.match('^[0-9a-f]+: +48 3d 01 f0 ff ff +cmp +rax, 0xfffffffffffff001$', lines[1]) is not None

replacement = pwn.asm(f'call {aeskeygenassist_rva:#x}', ioctl + text_delta)
assert len(replacement) <= 8
replacement = replacement.ljust(8, b'\x90')

prefix = pwn.asm(f'''
    push rax
    push rdi
    push rsi
    push rdx
    lea rsi, [rip]
''')
payload = prefix + pwn.asm(f'''
    sub rsi, {aeskeygenassist_rva + len(prefix):#x}
    mov rdx, [rdx + 8]
    sub rdx, rsi
    push rdx
    mov rsi, rsp
    mov edx, 8
    mov edi, 1
    mov eax, 1
    syscall
    pop rdx

    pop rdx
    pop rsi
    pop rdi
    pop rax

    syscall
    cmp rax, 0xfffffffffffff001
    ret
''')

patched_elf = bytearray(elf)
patched_elf[ioctl:ioctl + 8] = replacement
patched_elf[aeskeygenassist_rva - text_delta:aeskeygenassist_rva - text_delta + len(payload)] = payload

def write_patched_in(directory: str | pathlib.Path) -> pathlib.Path:
    patched_file = pathlib.Path(directory) / 'chekhov.patched'
    patched_file.write_bytes(patched_elf)
    patched_file.chmod(0o500)
    return patched_file

def run_patched(path: pathlib.Path, prefix: list[str] = []):
    return subprocess.run(prefix + [str(path), '-'.join(['AAAAAA'] * 8)], capture_output=True)

def run_and_maybe_set_capabilities(path: pathlib.Path, prefix: list[str] = []):
    process = run_patched(path, prefix)
    if b'please setcap' in process.stderr:
        # Ah yikes. We have to setcap the patched binary.
        print(process.stderr.decode(errors='ignore').strip())
        subprocess.run([
            'sudo', 'setcap', 'cap_dac_read_search=ep cap_sys_ptrace=ep', str(path)
        ], check=True)
        process = run_patched(path, prefix)
    return process

def run_in_tempdir(parent: pathlib.Path | None = None, prefix: list[str] = []):
    with tempfile.TemporaryDirectory(dir=parent) as temp_dir:
        path = write_patched_in(temp_dir)
        return run_and_maybe_set_capabilities(path, prefix)

order = []

process = run_in_tempdir()
if b'please setcap' in process.stderr:
    print('\x1b[1;31mSetting capabilities was insufficient (maybe /tmp is a nosuid mount?), trying in current directory\x1b[0m')
    process = run_in_tempdir(pathlib.Path('.').absolute())
if b'please setcap' in process.stderr:
    subprocess.run(['sudo', '-k'], check=True) # Require re-entering the password for this.
    print('\x1b[1;31mRunning in the local directory was also insufficient, running as root\x1b[0m')
    process = run_in_tempdir(prefix=['sudo'])
assert len(process.stdout) == 8 * 64 * 2

for index, tup in enumerate(struct.iter_unpack('Q', process.stdout)):
    if index % 2:
        continue
    source_rva = tup[0]
    reloc_addr = next(key for key, value in relocs.items() if value == source_rva)
    check_id = (reloc_addr - reloc_base) // 8
    order.append(check_id)

# Sanity check that this is correct
assert order == [ 527, 454, 113, 397, 427, 629, 312, 176, 373, 334, 939, 354, 554, 167, 780, 757, 999, 1015, 286, 313, 172, 316, 333, 147, 693, 42 , 419, 349, 240, 226, 767, 230, 267, 691, 918, 481, 256, 560, 916, 266, 677, 186, 818, 500, 553, 737, 33 , 275, 793, 1004, 613, 450, 781, 108, 252, 741, 522, 938, 852, 111, 699, 567, 170, 639, ]

OPS = { 'add': operator.add, 'xor': operator.xor }

key = z3.BitVec('key', 256)

solver = z3.Solver()
for index, check_id in enumerate(order):
    check_fn = relocs[reloc_base + check_id * 8]
    print(f'Check {index}: #{check_id} (at {check_fn:#x})')
    check_fn_bytes = elf[check_fn - text_delta:check_fn - text_delta + 0x240]
    assembly = pwn.disasm(check_fn_bytes, check_fn)
    assembly = re.split(r'(?<=ret$)', assembly, maxsplit=1, flags=re.MULTILINE)[0]
    constants = [int(m.group(1), 0) for m in re.finditer(r'movabs r[ac]x, (0x[0-9a-f]+)', assembly)]
    assert len(constants) == 5
    masks, expected = constants[:4], constants[4]
    masks = [masks[1], masks[0], masks[3], masks[2]] # lol ordering
    mask = functools.reduce(operator.or_, (m << (64 * i) for i, m in enumerate(masks)))
    assert mask.bit_count() == 50
    mask |= (0xff << (8 * (index % 16))) | (0xff << (8 * ((index % 16) + 16)))
    bits = [index for index in range(256) if mask & (1 << index)]

    packed_chunks = []
    for chunk in range(4):
        chunk_mask = ((mask >> (64 * chunk)) & ((1 << 64) - 1))
        bit_count = chunk_mask.bit_count()
        bits = [64 * chunk + i for i in range(64) if chunk_mask & (1 << i)]
        packed_chunk = z3.Concat(*[z3.Extract(index, index, key) for index in bits[::-1]])
        assert isinstance(packed_chunk, z3.BitVecRef)
        assert packed_chunk.sort().size() == bit_count
        packed_chunks.append(packed_chunk)
    packed = z3.Concat(*packed_chunks)
    assert isinstance(packed, z3.BitVecRef)
    if packed.sort().size() != 64:
        packed = z3.ZeroExt(64 - packed.sort().size(), packed)
    packed = z3.simplify(packed)

    assembly = assembly[assembly.index('vpslldq'):] # Remove the header, we don't need it
    segments = re.split(r'(?:mov\s+al, BYTE PTR \[rsp(?:-0x[0-8])?\]|(?=movabs))', assembly)[1:-1]
    assert len(segments) == 8
    total = z3.BitVecVal(0, 64)
    for byte_index, segment in enumerate(segments):
        byte = z3.simplify(z3.Extract(byte_index * 8 + 7, byte_index * 8, packed))
        assert isinstance(byte, z3.BitVecRef)
        assert byte.sort().size() == 8

        total = z3.RotateLeft(total, 4)

        assert (match := re.search(r'mov\s+esi, ([0-9a-fx]+)', segment))
        factor = int(match.group(1), 0)
        assert (match := re.search(r'(add|xor)\s+eax, ([0-9a-fx]+)', segment))
        addend = int(match.group(2), 0)
        add_op = OPS[match.group(1)]
        assert (match := re.search(r'(add|xor)\s+rdi, rax', segment))
        combine_op = OPS[match.group(1)]

        total = combine_op(total, z3.ZeroExt(56, add_op(addend, factor * byte)))

    assert isinstance(total, z3.BitVecRef)
    assert total.sort().size() == 64
    total = z3.simplify(total)

    solver.add(expected == total)

assert solver.check() == z3.sat
model = solver.model()
key_bytes = model.eval(key).as_long().to_bytes(32, 'little') # pyright: ignore

parts = []
for index in range(0, len(key_bytes), 4):
    dword = int.from_bytes(key_bytes[index:index + 4], 'little')
    letters = ''
    for _ in range(6):
        letters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'[dword % 36] + letters
        dword //= 36
    assert dword == 0
    parts.append(letters)
solution = '-'.join(parts)
print(solution)

ciphertext = elf[0x6830:0x6830 + 7 * 16]
plaintext = AES.new(key=key_bytes, mode=AES.MODE_ECB).decrypt(ciphertext)
try:
    print(plaintext.rstrip(b'\0').decode())
except UnicodeDecodeError:
    print(plaintext)

assert solution == '7DNBUY-QB4VQM-HQSIH2-01IZKK-B5GELG-R58XGA-RTIKST-D1757X'
