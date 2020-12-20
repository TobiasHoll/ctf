import argparse
import hashlib
import struct
import sys
import time
import z3

try:
    from elftools.elf.elffile import ELFFile
    from capstone import *
    from capstone.x86 import *
    from unicorn import *
    from unicorn.x86_const import *
    may_validate = True
except ImportError:
    may_validate = False

flag_hash = bytes.fromhex('306f0306bc6b9b571a52f0596798ae42')
flag_length = 30
hash_mask = 0x3ff

hash_intermediaries = [
    941, 339, 875, 28, 38, 135, 809, 706, 183, 825, 130, 465, 629, 174, 414,
    647, 177, 476, 581, 853, 921, 115, 316, 815, 256, 474, 706, 743, 970, 909,
    424, 936, 812, 260, 996, 1, 864, 744, 713, 390, 603, 198, 357, 779, 715,
    679, 436, 867, 345, 494, 559, 1023, 795, 716, 476, 186, 284, 879, 893, 374,
    47, 1009, 284, 51
]


# MD5 compression function for Z3
s = [ 7, 12, 17, 22 ] * 4 + [ 5,  9, 14, 20 ] * 4 + [ 4, 11, 16, 23 ] * 4 + [ 6, 10, 15, 21 ] * 4
K = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]

def md5_compress(M, a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476):
    assert len(M) == 16
    neg = lambda n: (n ^ 0xFFFFFFFF) if isinstance(n, int) else ~n # z3 supports ~ properly
    restrict = lambda v: (v & 0xFFFFFFFF) if isinstance(v, int) else v # z3 already restricted
    shr = lambda v, s: (v >> s) if isinstance(v, int) else z3.LShR(v, s)
    rol = lambda v, s: restrict((v << s) | shr(v, 32 - s))
    A, B, C, D = a, b, c, d
    intermediate = []
    for i in range(64):
        if 0 <= i <= 15:
            F = (B & C) | (neg(B) & D)
            g = i
        elif 16 <= i <= 31:
            F = (D & B) | (neg(D) & C)
            g = (5 * i + 1) % 16
        elif 32 <= i <= 47:
            F = B ^ C ^ D
            g = (3 * i + 5) % 16
        elif 48 <= i <= 63:
            F = C ^ (B | neg(D))
            g = (7 * i) % 16
        F = restrict(F + A + K[i] + M[g])
        A = restrict(rol(F, s[i]) + B)
        cvt = lambda v: z3.BitVecVal(v, 32) if isinstance(v, int) else v
        intermediate.append(cvt(A) & hash_mask)
        A, B, C, D = D, A, B, C
    a, b, c, d = restrict(a + A), restrict(b + B), restrict(c + C), restrict(d + D)
    return a, b, c, d, intermediate


# Verify the hash values with those in the binary
def check_binary(path='restless'):
    assert may_validate, 'Failed to import required dependencies (elftools, capstone, unicorn)'
    with open(path, 'rb') as binary_file:
        binary = binary_file.read()

    dis = Cs(CS_ARCH_X86, CS_MODE_64)
    emu = Uc(UC_ARCH_X86, UC_MODE_64)
    dis.detail = True

    # Map memory
    stack = (0x7fffffff0000, 0xf000)
    alloc = (0x6fffffff0000, 0xf000)
    emu.mem_map(*stack, UC_PROT_READ | UC_PROT_WRITE)
    emu.reg_write(UC_X86_REG_RSP, stack[0] + stack[1] // 2)
    emu.mem_map(*alloc, UC_PROT_READ | UC_PROT_WRITE)
    emu.reg_write(UC_X86_REG_R15, alloc[0] + alloc[1] // 2)

    # Map binary (ignoring relocations, so we need to do some hooking)
    executable = (0x0, (len(binary) | 0xfff) + 1)
    emu.mem_map(*executable, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
    emu.mem_write(executable[0], binary)

    # Emulate the code that creates the list of intermediaries (sub_114F0)
    emu.emu_start(0x11531, 0x11539) # Set up r13
    emu.emu_start(0x116ed, 0x11700) # Set up r11
    emu.emu_start(0x117b6, 0x12710) # Stop before the resume

    # Some of the links in the list created by emulation are still screwed, but
    # the values should be there, and in order.
    memory = emu.mem_read(emu.reg_read(UC_X86_REG_R15) + 24, 64 * 2 * 8)
    tagged = struct.unpack(f'{64 * 2}Q', memory)[::2]
    assert all(value >> 48 == 0xa000 for value in tagged), 'Non-integer value in list'
    binary_intermediaries = [value & 0xffffffffffff for value in tagged][::-1]

    # Fetch the flag length
    for ins in dis.disasm(binary[0x140c0:0x140ca], 0x140c0):
        assert ins.id == X86_INS_MOVABS
        value = ins.operands[1]
        assert value.type == X86_OP_IMM
        positive = struct.unpack('Q', struct.pack('q', value.value.imm))[0]
        assert positive >> 48 == 0xa000, 'Non-integer flag length'
        binary_flag_length = positive & 0xffffffffffff
        break

    # Fetch the hash mask
    for ins in dis.disasm(binary[0x10598:0x105a2], 0x10598):
        assert ins.id == X86_INS_MOVABS
        value = ins.operands[1]
        assert value.type == X86_OP_IMM
        positive = struct.unpack('Q', struct.pack('q', value.value.imm))[0]
        assert positive >> 48 == 0xa000, 'Non-integer hash mask'
        binary_hash_mask = positive & 0xffffffffffff
        break

    # Fetch the hash value
    binary_flag_hash = binary[0x15018:0x15028]

    assert binary_flag_hash == flag_hash
    assert binary_flag_length == flag_length
    assert binary_hash_mask == hash_mask
    assert binary_intermediaries == hash_intermediaries
    print(f'\x1b[32mValues validated against binary \'{path}\'.\x1b[0m')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--binary', help='The challenge binary (to verify the extracted values)')
    parser.add_argument('-s', '--start', help='The number of intermediate values to start with', default=16, type=int)
    parser.add_argument('-i', '--increment', help='By how much to increment the number of intermediate values if the solution fails or is not unique', default=2, type=int)
    args = parser.parse_args()

    if args.binary:
        check_binary(args.binary)

    # Evaluate MD5 symbolically
    message = [z3.BitVec('m{:02d}'.format(i), 32) for i in range(16)]
    a, b, c, d, symbolic_intermediaries = md5_compress(message)

    # The intermediaries must match. This will be enough to constrain the entire thing
    equations = [
        first == second
        for first, second
        in zip(hash_intermediaries, symbolic_intermediaries)
    ]

    def constrain_message(s):
        # The last two words contain the length of the flag in bits, in little-endian
        s.add(message[15] == 0)
        s.add(message[14] == z3.BitVecVal(flag_length * 8, 32))

        # There are a lot of zero-words before that
        for i in range(8, 14, 1):
            s.add(message[i] == 0) # 0-parts of message

        # Word 7 contains one byte of data and the 0x80 padding byte
        s.add(message[7] & 0xffff0000 == 0x800000)

        # Constrain the remaining bytes to printable ASCII
        s.add((message[7] & 0xff00) >= 0x2000)
        s.add((message[7] & 0xff00) < 0x7f00)
        s.add((message[7] & 0xff) >= 0x20)
        s.add((message[7] & 0xff) < 0x7f)
        for i in range(0, 7, 1):
            for shift in range(0, 32, 8):
                s.add((message[i] & (0xff << shift)) >= (0x20 << shift))
                s.add((message[i] & (0xff << shift)) <= (0x7e << shift))

    def constrain_intermediaries(s, count):
        # Add the intermediaries
        for i in range(min(len(equations), count)):
            s.add(equations[i])

    used = args.start
    while True:
        start = time.time()
        s = z3.Solver()
        constrain_message(s)
        constrain_intermediaries(s, used)
        solvable = s.check()
        assert solvable == z3.sat
        m = s.model()
        end = time.time()
        raw = struct.pack('<' + 'I' * 16, *[m.eval(block).as_long() for block in message])
        actual = raw[:-8].rstrip(b'\x00')[:-1]
        print(f'{used:02d}\t{actual.decode()}  ({end - start:03.5f}s)', file=sys.stderr)
        if hashlib.md5(actual).digest() != flag_hash:
            # Constrain further
            used += args.increment
            continue
        else:
            flag = 'hxp{' + actual.decode() + '}'
            print(f'\x1b[32;1m{flag}\x1b[0m')
            break
