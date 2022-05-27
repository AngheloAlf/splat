#! /usr/bin/env python3

import argparse
import spimdisasm


def int_any_base(x):
    return int(x, 0)


parser = argparse.ArgumentParser(
    description="Given a rom and start offset, find where the code ends"
)
parser.add_argument("rom", help="path to a .z64 rom")
parser.add_argument("start", help="start offset", type=int_any_base)
parser.add_argument("--end", help="end offset", default=None, type=int_any_base)
parser.add_argument(
    "--vram",
    help="vram address to start disassembly at",
    default="0x80000000",
    type=int_any_base,
)


def run(rom_bytes, start_offset, vram, end_offset=None):
    rom_addr = start_offset
    last_return = rom_addr

    wordList = spimdisasm.common.Utils.bytesToBEWords(rom_bytes[start_offset:])

    for word in wordList:
        insn = spimdisasm.mips.instructions.wordToInstruction(word)
        insn.vram = vram

        if not insn.isImplemented():
            break

        # insn.rs == $ra
        if (
            insn.uniqueId == spimdisasm.mips.instructions.InstructionId.JR
            and insn.rs == 31
        ):
            last_return = rom_addr
        rom_addr += 4
        vram += 4
        if end_offset and rom_addr >= end_offset:
            break

    # align to next 0x10 boundary
    end = last_return + 0x10
    end -= end % 0x10
    return end


def main():
    args = parser.parse_args()

    with open(args.rom, "rb") as f:
        rom_bytes = f.read()

    start = args.start
    end = args.end
    vram = args.vram

    print(f"0x{run(rom_bytes, start, vram, end):X}")


if __name__ == "__main__":
    main()
