from pathlib import Path
from typing import Optional

from .asm import CommonSegAsm

from ...util import options, symbols

import spimdisasm


class CommonSegHasm(CommonSegAsm):
    def out_path(self) -> Optional[Path]:
        if options.opts.hasm_in_src_path and not options.opts.disassemble_all:
            return options.opts.src_path / self.dir / f"{self.name}.s"

        return super().out_path()

    def scan(self, rom_bytes: bytes):
        if (
            self.rom_start is not None
            and self.rom_end is not None
            and self.rom_start != self.rom_end
        ):
            self.scan_code(rom_bytes, is_hasm=True)

    def split(self, rom_bytes: bytes):
        if not self.rom_start == self.rom_end and self.spim_section is not None:
            out_path = self.out_path()
            if out_path and not out_path.exists():
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
                    sym_count = self.spim_section.get_section().sym_count()
                    for i in range(sym_count):
                        f.write(self.spim_section.get_section().display_sym(symbols.spim_context, i, settings))
                        if i + 1 != sym_count:
                            f.write("\n")
