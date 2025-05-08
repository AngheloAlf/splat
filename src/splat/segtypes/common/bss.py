from typing import Optional

from ...util import options, symbols, log

from .data import CommonSegData

from ...disassembler.disassembler_section import DisassemblerSection, make_bss_section

# If `options.opts.ld_bss_is_noload` is False, then this segment behaves like a `CommonSegData`

import spimdisasm

class CommonSegBss(CommonSegData):
    def get_linker_section(self) -> str:
        return ".bss"

    def get_section_flags(self) -> Optional[str]:
        return "wa"

    @staticmethod
    def is_data() -> bool:
        if not options.opts.ld_bss_is_noload:
            return True
        return False

    @staticmethod
    def is_noload() -> bool:
        if not options.opts.ld_bss_is_noload:
            return False
        return True

    def configure_disassembler_section(
        self, disassembler_section: DisassemblerSection
    ) -> None:
        "Allows to configure the section before running the analysis on it"

        pass

    def disassemble_data(self, rom_bytes: bytes):
        if not options.opts.ld_bss_is_noload:
            super().disassemble_data(rom_bytes)
            return

        if self.is_auto_segment:
            return

        if not isinstance(self.rom_start, int):
            log.error(
                f"Segment '{self.name}' (type '{self.type}') requires a rom_start. Got '{self.rom_start}'"
            )

        # Supposedly logic error, not user error
        assert isinstance(self.rom_end, int), f"{self.name} {self.rom_end}"

        # Supposedly logic error, not user error
        segment_rom_start = self.get_most_parent().rom_start
        assert isinstance(segment_rom_start, int), f"{self.name} {segment_rom_start}"

        if not isinstance(self.vram_start, int):
            log.error(
                f"Segment '{self.name}' (type '{self.type}') requires a vram address. Got '{self.vram_start}'"
            )

        next_subsegment = self.parent.get_next_subsegment_for_ram(self.vram_start, self.index_within_group)
        if next_subsegment is None:
            bss_end = self.get_most_parent().vram_end
        else:
            bss_end = next_subsegment.vram_start
        assert isinstance(bss_end, int), f"{self.name} {bss_end}"

        self.spim_section = make_bss_section(
            self.rom_start,
            self.rom_end,
            self.vram_start,
            bss_end,
            self.name,
            segment_rom_start,
            self.get_exclusive_ram_id(),
        )

        assert self.spim_section is not None

        self.configure_disassembler_section(self.spim_section)

        self.spim_section.analyze()
        # self.spim_section.set_comment_offset(self.rom_start)
        return

        for sym_index in range(self.spim_section.get_section().sym_count()):
            generated_symbol = symbols.create_symbol_from_spim_symbol(
                self.get_most_parent(), *self.spim_section.get_section().get_sym_info(symbols.spim_context, sym_index)
            )
            self.spim_section.get_section().set_sym_name(symbols.spim_context, sym_index, generated_symbol.name)

    def should_scan(self) -> bool:
        if not options.opts.ld_bss_is_noload:
            return super().should_scan()
        return options.opts.is_mode_active("code") and self.vram_start is not None and self.vram_start != self.vram_end

    @property
    def size(self) -> Optional[int]:
        if self.vram_start is None:
            return None

        next_subsegment = self.parent.get_next_subsegment_for_ram(self.vram_start, self.index_within_group)
        if next_subsegment is None:
            bss_end = self.get_most_parent().vram_end
        else:
            bss_end = next_subsegment.vram_start

        if bss_end is None:
            return None

        return bss_end - self.vram_start

    def split(self, rom_bytes: bytes):
        if self.type.startswith(".") and not options.opts.disassemble_all:
            return

        if self.spim_section is None or not self.should_self_split():
            return

        path = self.asm_out_path()

        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("w", newline="\n") as f:
            f.write('.include "macro.inc"\n\n')
            preamble = options.opts.generated_s_preamble
            if preamble:
                f.write(preamble + "\n")

            f.write(f"{self.get_section_asm_line()}\n\n")

            settings = spimdisasm.SymNobitsDisplaySettings()
            settings.set_rom_comment_width(6 if options.opts.rom_address_padding else 0 )

            sym_count = self.spim_section.get_section().sym_count()
            for i in range(sym_count):
                f.write(self.spim_section.get_section().display_sym(symbols.spim_context, i, settings))
                if i + 1 != sym_count:
                    f.write("\n")
