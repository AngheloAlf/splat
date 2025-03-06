from typing import Optional

import spimdisasm
import rabbitizer

from ...util import options, symbols, log, relocs

from .code import CommonSegCode

from ..segment import Segment, parse_segment_vram

from ...disassembler.disassembler_section import DisassemblerSection, make_text_section

import spimdisasm

# abstract class for c, asm, data, etc
class CommonSegCodeSubsegment(Segment):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        vram = parse_segment_vram(self.yaml)
        if vram is not None:
            self.vram_start = vram

        self.str_encoding: Optional[str] = (
            self.yaml.get("str_encoding", None) if isinstance(self.yaml, dict) else None
        )

        self.spim_section: Optional[DisassemblerSection] = None
        self.instr_category = rabbitizer.InstrCategory.CPU
        if options.opts.platform == "ps2":
            self.instr_category = rabbitizer.InstrCategory.R5900
        elif options.opts.platform == "psx":
            self.instr_category = rabbitizer.InstrCategory.R3000GTE
        elif options.opts.platform == "psp":
            self.instr_category = rabbitizer.InstrCategory.R4000ALLEGREX

        self.detect_redundant_function_end: Optional[bool] = (
            self.yaml.get("detect_redundant_function_end", None)
            if isinstance(self.yaml, dict)
            else None
        )

        self.is_hasm = False
        self.use_gp_rel_macro = options.opts.use_gp_rel_macro

    @property
    def needs_symbols(self) -> bool:
        return True

    def get_linker_section(self) -> str:
        return ".text"

    def configure_disassembler_section(
        self, disassembler_section: DisassemblerSection
    ) -> None:
        return
        "Allows to configure the section before running the analysis on it"

        section = disassembler_section.get_section()

        section.isHandwritten = self.is_hasm
        section.instrCat = self.instr_category
        section.detectRedundantFunctionEnd = self.detect_redundant_function_end
        section.gpRelHack = not self.use_gp_rel_macro

    def scan_code(self, rom_bytes, is_hasm=False):
        self.is_hasm = is_hasm

        if self.is_auto_segment:
            return

        if not isinstance(self.rom_start, int):
            log.error(
                f"Segment '{self.name}' (type '{self.type}') requires a rom_start. Got '{self.rom_start}'"
            )

        # Supposedly logic error, not user error
        assert isinstance(self.rom_end, int), self.rom_end

        # Supposedly logic error, not user error
        segment_rom_start = self.get_most_parent().rom_start
        assert isinstance(segment_rom_start, int), segment_rom_start

        if not isinstance(self.vram_start, int):
            log.error(
                f"Segment '{self.name}' (type '{self.type}') requires a vram address. Got '{self.vram_start}'"
            )

        self.spim_section = make_text_section(
            self.rom_start,
            self.rom_end,
            self.vram_start,
            self.name,
            rom_bytes[self.rom_start:self.rom_end],
            segment_rom_start,
            self.get_exclusive_ram_id(),
        )

        assert self.spim_section is not None

        self.configure_disassembler_section(self.spim_section)

        self.spim_section.analyze()

        # self.spim_section.set_comment_offset(self.rom_start)

    def print_file_boundaries(self):
        return
        if not self.show_file_boundaries or not self.spim_section:
            return

        assert isinstance(self.rom_start, int)

        for in_file_offset in self.spim_section.get_section().fileBoundaries:
            if not self.parent.reported_file_split:
                self.parent.reported_file_split = True

                # Look up for the last symbol in this boundary
                sym_addr = 0
                for sym in self.spim_section.get_section().symbolList:
                    symOffset = (
                        sym.inFileOffset - self.spim_section.get_section().inFileOffset
                    )
                    if in_file_offset == symOffset:
                        break
                    sym_addr = sym.vram

                print(
                    f"\nSegment {self.name}, symbol at vram {sym_addr:X} ends with extra nops, indicating a likely file split."
                )
                print(
                    "File split suggestions for this segment will follow in config yaml format:"
                )
            print(f"      - [0x{self.rom_start+in_file_offset:X}, {self.type}]")

    def post_process(self):
        if self.spim_section is not None:
            section = self.spim_section.get_section()
            section.post_process(symbols.spim_context, relocs.all_relocs)

            for sym_index in range(section.sym_count()):
                generated_symbol = symbols.create_symbol_from_spim_symbol(
                    self.get_most_parent(), *section.get_sym_info(symbols.spim_context, sym_index)
                )
                section.set_sym_name(symbols.spim_context, sym_index, generated_symbol.name)
                generated_symbol.linker_section = self.get_linker_section_linksection()

                for label_index in range(section.label_count_for_sym(sym_index)):
                    generated_label = symbols.create_symbol_from_spim_label(
                        self.get_most_parent(), *section.get_label_info(symbols.spim_context, sym_index, label_index)
                    )
                    if generated_label is not None:
                        section.set_label_name(symbols.spim_context, sym_index, label_index, generated_label.name)


    def should_scan(self) -> bool:
        return (
            options.opts.is_mode_active("code")
            and self.rom_start is not None
            and self.rom_end is not None
            and self.vram_start != self.vram_end
        )

    def should_split(self) -> bool:
        return (
            self.extract and options.opts.is_mode_active("code") and self.should_scan()
        )  # only split if the segment was scanned first
