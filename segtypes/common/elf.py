import spimdisasm

from segtypes.common.code import CommonSegCode
from util import options

# elf group
class CommonSegElf(CommonSegCode):
    def scan(self, rom_bytes):
        self.elf_file = spimdisasm.elf32.Elf32File(rom_bytes)

        if self.elf_file.header.ident.getDataEncoding() == spimdisasm.elf32.Elf32HeaderIdentifier.DataEncoding.DATA2MSB:
            options.opts["endianess"] = "big"
        else:
            options.opts["endianess"] = "little"

        # TODO: add symbols from elf

        super().scan(rom_bytes)
