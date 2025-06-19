#!/usr/bin/env python3

import argparse
import pathlib
import textwrap

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('text', help='IOU .text section', type=pathlib.Path)
    parser.add_argument('rodata', help='IOU .rodata section', type=pathlib.Path)
    parser.add_argument('include', help='Generated C include file', type=pathlib.Path)
    parser.add_argument('assembly', help='Generated assembly source file', type=pathlib.Path)
    parser.add_argument('--scratch', help='Address of the scratch buffer in the IOU code', default=0xf4100000, type=lambda v: int(v, 0))
    parser.add_argument('--constants', help='Address of the constants buffer in the IOU code', default=0xf4200000, type=lambda v: int(v, 0))
    parser.add_argument('--scratch-size', help='Size of the scratch space', default=8, type=lambda v: int(v, 0))
    args = parser.parse_args()

    text = args.text.read_bytes()
    rodata = args.rodata.read_bytes()

    rodata_bytes = ', '.join(hex(byte) for byte in rodata)

    with open(args.assembly, 'w') as asm:
        emit = lambda text: asm.write(textwrap.dedent(text.rstrip()).strip() + '\n')
        emit(f'''
            .section .bss
            .p2align 12
            .lcomm scratch, {args.scratch_size}

            .section .data
            .local constants
            .size constants, {len(rodata)}
            .type constants, STT_OBJECT
            constants:
                .byte {rodata_bytes}

            .global buffers
            .size buffers, 32
            .type buffers, STT_OBJECT
            buffers:
                .8byte scratch, {args.scratch_size}, constants, {len(rodata)}

            .global sqes
            .size sqes, {len(text)}
            .type sqes, STT_OBJECT
            sqes:
        ''')

        for offset in range(0, len(text), 8):
            qword = text[offset:offset + 8]
            qword = int.from_bytes(qword, 'little')
            masked = qword & 0xfffffffffff00000
            if masked == args.scratch:
                emit(f'.8byte (scratch + {hex(qword - args.scratch)})')
            elif masked == args.constants:
                emit(f'.8byte (constants + {hex(qword - args.constants)})')
            else:
                emit('.8byte ' + hex(qword))

    with open(args.include, 'w') as inc:
        inc.write(textwrap.dedent(f'''
            #define SQE_COUNT ({len(text) // 64})
            extern struct iovec buffers[2];
            extern struct io_uring_sqe sqes[SQE_COUNT];
        '''))

