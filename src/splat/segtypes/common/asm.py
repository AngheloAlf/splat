from pathlib import Path
from typing import Optional, List

from ...util import options, symbols

from .codesubsegment import CommonSegCodeSubsegment

import spimdisasm

class CommonSegAsm(CommonSegCodeSubsegment):
    @staticmethod
    def is_text() -> bool:
        return True

    def get_section_flags(self) -> Optional[str]:
        return "ax"

    def out_path(self) -> Optional[Path]:
        return options.opts.asm_path / self.dir / f"{self.name}.s"

    def scan(self, rom_bytes: bytes):
        if (
            self.rom_start is not None
            and self.rom_end is not None
            and self.rom_start != self.rom_end
        ):
            self.scan_code(rom_bytes)

    def get_file_header(self) -> List[str]:
        ret = []

        ret.append('.include "macro.inc"')
        ret.append("")
        ret.append(".set noat")  # allow manual use of $at
        ret.append(".set noreorder")  # don't insert nops after branches
        if options.opts.add_set_gp_64:
            ret.append(".set gp=64")  # allow use of 64-bit general purpose registers
        ret.append("")
        preamble = options.opts.generated_s_preamble
        if preamble:
            ret.append(preamble)
            ret.append("")

        ret.append(self.get_section_asm_line())
        ret.append("")

        return ret

    def split(self, rom_bytes: bytes):
        if not self.rom_start == self.rom_end and self.spim_section is not None:
            out_path = self.out_path()
            if out_path:
                out_path.parent.mkdir(parents=True, exist_ok=True)

                self.print_file_boundaries()

                with open(out_path, "w", newline="\n") as f:
                    for line in self.get_file_header():
                        f.write(line + "\n")

                    display_flags = spimdisasm.InstructionDisplayFlags.new_gnu_as()
                    display_flags.set_named_gpr(options.opts.mips_abi_gpr != "numeric")
                    display_flags.set_named_fpr(options.opts.mips_abi_float_regs != "numeric")
                    display_flags.set_opcode_ljust(options.opts.mnemonic_ljust - 1)

                    settings = spimdisasm.FunctionDisplaySettings(display_flags)
                    settings.set_rom_comment_width(6 if options.opts.rom_address_padding else 0 )
                    sym_count = self.spim_section.get_section().sym_count()
                    for i in range(sym_count):
                        f.write(self.spim_section.get_section().display_sym(symbols.spim_context, i, settings))
                        if i + 1 != sym_count:
                            f.write("\n")
