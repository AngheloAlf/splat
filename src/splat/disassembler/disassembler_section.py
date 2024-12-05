from abc import ABC, abstractmethod
from typing import Optional

import spimdisasm

from ..util import options, symbols


class DisassemblerSection(ABC):
    @abstractmethod
    def disassemble(self):
        raise NotImplementedError("disassemble")

    @abstractmethod
    def analyze(self):
        raise NotImplementedError("analyze")

    @abstractmethod
    def set_comment_offset(self, rom_start: int):
        raise NotImplementedError("set_comment_offset")

    @abstractmethod
    def make_bss_section(
        self,
        rom_start,
        rom_end,
        vram_start,
        bss_end,
        name,
        segment_rom_start,
        exclusive_ram_id,
    ):
        raise NotImplementedError("make_bss_section")

    @abstractmethod
    def make_data_section(
        self,
        rom_start,
        rom_end,
        vram_start,
        name,
        rom_bytes,
        segment_rom_start,
        exclusive_ram_id,
    ):
        raise NotImplementedError("make_data_section")

    @abstractmethod
    def get_section(self):
        raise NotImplementedError("get_section")

    @abstractmethod
    def make_rodata_section(
        self,
        rom_start,
        rom_end,
        vram_start,
        name,
        rom_bytes,
        segment_rom_start,
        exclusive_ram_id,
    ):
        raise NotImplementedError("make_rodata_section")

    @abstractmethod
    def make_text_section(
        self,
        rom_start,
        rom_end,
        vram_start,
        name,
        rom_bytes,
        segment_rom_start,
        exclusive_ram_id,
    ):
        raise NotImplementedError("make_text_section")


class SpimdisasmDisassemberSection(DisassemblerSection):
    def __init__(self):
        self.spim_section = None

    def disassemble(self) -> str:
        assert False
        # return self.spim_section.disassemble()

    def analyze(self):
        return
        assert self.spim_section is not None
        self.spim_section.analyze()

    def set_comment_offset(self, rom_start: int):
        return
        assert self.spim_section is not None
        self.spim_section.setCommentOffset(rom_start)

    def make_bss_section(
        self,
        rom_start: int,
        rom_end: int,
        vram_start: int,
        bss_end: int,
        name: str,
        segment_rom_start: int,
        exclusive_ram_id,
    ):
        settings = spimdisasm.SectionNoloadSettings()
        parent_segment_info = spimdisasm.ParentSegmentInfo(
            spimdisasm.RomAddress(segment_rom_start),
            vram_start, # TODO: use segment's vram instead
            spimdisasm.OverlayCategoryName(exclusive_ram_id) if exclusive_ram_id is not None else None
        )
        self.spim_section = symbols.spim_context.create_section_bss(
            settings,
            name,
            vram_start,
            bss_end,
            parent_segment_info,
        )

    def make_data_section(
        self,
        rom_start: int,
        rom_end: int,
        vram_start: int,
        name: str,
        rom_bytes: bytes,
        segment_rom_start: int,
        exclusive_ram_id,
    ):
        settings = spimdisasm.SectionDataSettings()
        parent_segment_info = spimdisasm.ParentSegmentInfo(
            spimdisasm.RomAddress(segment_rom_start),
            vram_start, # TODO: use segment's vram instead
            spimdisasm.OverlayCategoryName(exclusive_ram_id) if exclusive_ram_id is not None else None
        )
        self.spim_section = symbols.spim_context.create_section_data(
            settings,
            name,
            rom_bytes,
            spimdisasm.RomAddress(rom_start),
            vram_start,
            parent_segment_info,
        )

    def get_section(self):
        return self.spim_section

    def make_rodata_section(
        self,
        rom_start: int,
        rom_end: int,
        vram_start: int,
        name: str,
        rom_bytes: bytes,
        segment_rom_start: int,
        exclusive_ram_id,
    ):
        settings = spimdisasm.SectionDataSettings()
        parent_segment_info = spimdisasm.ParentSegmentInfo(
            spimdisasm.RomAddress(segment_rom_start),
            vram_start, # TODO: use segment's vram instead
            spimdisasm.OverlayCategoryName(exclusive_ram_id) if exclusive_ram_id is not None else None
        )
        self.spim_section = symbols.spim_context.create_section_rodata(
            settings,
            name,
            rom_bytes,
            spimdisasm.RomAddress(rom_start),
            vram_start,
            parent_segment_info,
        )

    def make_text_section(
        self,
        rom_start: int,
        rom_end: int,
        vram_start: int,
        name: str,
        rom_bytes: bytes,
        segment_rom_start: int,
        exclusive_ram_id,
    ):
        settings = spimdisasm.SectionExecutableSettings()
        parent_segment_info = spimdisasm.ParentSegmentInfo(
            spimdisasm.RomAddress(segment_rom_start),
            vram_start, # TODO: use segment's vram instead
            spimdisasm.OverlayCategoryName(exclusive_ram_id) if exclusive_ram_id is not None else None
        )
        self.spim_section = symbols.spim_context.create_section_text(
            settings,
            name,
            rom_bytes,
            spimdisasm.RomAddress(rom_start),
            vram_start,
            parent_segment_info,
        )

    def make_gcc_except_table_section(
        self,
        rom_start: int,
        rom_end: int,
        vram_start: int,
        name: str,
        rom_bytes: bytes,
        segment_rom_start: int,
        exclusive_ram_id,
    ):
        settings = spimdisasm.SectionDataSettings()
        parent_segment_info = spimdisasm.ParentSegmentInfo(
            spimdisasm.RomAddress(segment_rom_start),
            vram_start, # TODO: use segment's vram instead
            spimdisasm.OverlayCategoryName(exclusive_ram_id) if exclusive_ram_id is not None else None
        )
        self.spim_section = symbols.spim_context.create_section_gcc_except_table(
            settings,
            name,
            rom_bytes,
            spimdisasm.RomAddress(rom_start),
            vram_start,
            parent_segment_info,
        )


def make_disassembler_section() -> Optional[SpimdisasmDisassemberSection]:
    if options.opts.platform in ["n64", "psx", "ps2", "psp"]:
        return SpimdisasmDisassemberSection()

    raise NotImplementedError("No disassembler section for requested platform")
    return None


def make_text_section(
    rom_start: int,
    rom_end: int,
    vram_start: int,
    name: str,
    rom_bytes: bytes,
    segment_rom_start: int,
    exclusive_ram_id,
) -> DisassemblerSection:
    section = make_disassembler_section()
    assert section is not None
    section.make_text_section(
        rom_start,
        rom_end,
        vram_start,
        name,
        rom_bytes,
        segment_rom_start,
        exclusive_ram_id,
    )
    return section


def make_data_section(
    rom_start: int,
    rom_end: int,
    vram_start: int,
    name: str,
    rom_bytes: bytes,
    segment_rom_start: int,
    exclusive_ram_id,
) -> DisassemblerSection:
    section = make_disassembler_section()
    assert section is not None
    section.make_data_section(
        rom_start,
        rom_end,
        vram_start,
        name,
        rom_bytes,
        segment_rom_start,
        exclusive_ram_id,
    )
    return section


def make_rodata_section(
    rom_start: int,
    rom_end: int,
    vram_start: int,
    name: str,
    rom_bytes: bytes,
    segment_rom_start: int,
    exclusive_ram_id,
) -> DisassemblerSection:
    section = make_disassembler_section()
    assert section is not None
    section.make_rodata_section(
        rom_start,
        rom_end,
        vram_start,
        name,
        rom_bytes,
        segment_rom_start,
        exclusive_ram_id,
    )
    return section


def make_bss_section(
    rom_start: int,
    rom_end: int,
    vram_start: int,
    bss_end: int,
    name: str,
    segment_rom_start: int,
    exclusive_ram_id,
) -> DisassemblerSection:
    section = make_disassembler_section()
    assert section is not None
    section.make_bss_section(
        rom_start,
        rom_end,
        vram_start,
        bss_end,
        name,
        segment_rom_start,
        exclusive_ram_id,
    )
    return section


def make_gcc_except_table_section(
    rom_start: int,
    rom_end: int,
    vram_start: int,
    name: str,
    rom_bytes: bytes,
    segment_rom_start: int,
    exclusive_ram_id,
) -> DisassemblerSection:
    section = make_disassembler_section()
    assert section is not None
    section.make_gcc_except_table_section(
        rom_start,
        rom_end,
        vram_start,
        name,
        rom_bytes,
        segment_rom_start,
        exclusive_ram_id,
    )
    return section
