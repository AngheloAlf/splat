from pathlib import Path
from typing import Optional

from .asm import CommonSegAsm

from ...util import options


class CommonSegHasm(CommonSegAsm):
    def asm_out_path(self) -> Optional[Path]:
        if options.opts.hasm_in_src_path:
            return options.opts.src_path / self.dir / f"{self.name}.s"

        return super().asm_out_path()

    def scan(self, rom_bytes: bytes):
        if (
            self.rom_start is not None
            and self.rom_end is not None
            and self.rom_start != self.rom_end
        ):
            self.scan_code(rom_bytes, is_hasm=True)

    def split(self, rom_bytes: bytes):
        if self.rom_start == self.rom_end:
            return

        self.split_as_asm_file(self.out_path())
