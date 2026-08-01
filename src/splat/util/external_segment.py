import dataclasses
from typing import Any, Optional, TYPE_CHECKING

from . import log

if TYPE_CHECKING:
    from ..segtypes.segment import Segment


@dataclasses.dataclass
class ExternalSegment:
    """
    Declaration for segments that are not part of the current binary.

    Is very common for PSX and PS2 games to have independent binaries that
    reference each other.
    We need to know all the existing segments so we can try to reference them
    properly and associate each symbol to the corresponding segment metadata.
    """

    name: str
    rom_start: int
    rom_end: int
    vram_start: int
    bss_size: Optional[int]
    is_global: bool
    exclusive_ram_id: Optional[str]

    @property
    def vram_end(self) -> int:
        rom_size = self.rom_end - self.rom_start
        bss_size = self.bss_size or 0
        return self.vram_start + rom_size + bss_size

    @staticmethod
    def from_yaml(ext_yaml: dict[str, Any]) -> "ExternalSegment":
        name = ext_yaml.get("name")
        rom_start = ext_yaml.get("rom_start")
        rom_end = ext_yaml.get("rom_end")
        vram = ext_yaml.get("vram")
        bss_size = ext_yaml.get("bss_size")
        is_global = ext_yaml.get("is_global") or False
        exclusive_ram_id = ext_yaml.get("exclusive_ram_id")

        if name is None:
            log.error("Missing name for external segment")
        if rom_start is None:
            log.error(f"Missing rom_start for external segment '{name}'")
        if rom_end is None:
            log.error(f"Missing rom_end for external segment '{name}'")
        if vram is None:
            log.error(f"Missing vram for external segment '{name}'")

        if is_global and exclusive_ram_id is not None:
            log.error(
                f"Can't declare external segment '{name}' as both is_global and exclusive_ram_id"
            )

        return ExternalSegment(
            name,
            rom_start,
            rom_end,
            vram,
            bss_size,
            is_global,
            exclusive_ram_id,
        )

    def compare_to_segment_and_log(self, seg: "Segment") -> bool:
        ret = True
        if self.name != seg.name:
            log.write(
                f"Error: The name of the segment '{seg.name}' does not match the external segment '{self.name}'.\n"
                f"  Expected {seg.name}, got {self.name}",
                status="warn",
            )
            ret = False
        if self.rom_start != seg.rom_start:
            log.write(
                f"Error: The rom_start of the segment '{seg.name}' does not match the external segment '{self.name}'.\n"
                f"  Expected {seg.rom_start}, got {self.rom_start}",
                status="warn",
            )
            ret = False
        if self.rom_end != seg.rom_end:
            log.write(
                f"Error: The rom_end of the segment '{seg.name}' does not match the external segment '{self.name}'.\n"
                f"  Expected {seg.rom_end}, got {self.rom_end}",
                status="warn",
            )
            ret = False
        if self.vram_start != seg.vram_start:
            log.write(
                f"Error: The vram of the segment '{seg.name}' does not match the external segment '{self.name}'.\n"
                f"  Expected {seg.vram_start}, got {self.vram_start}",
                status="warn",
            )
            ret = False
        if self.bss_size != seg.bss_size:
            log.write(
                f"Error: The bss_size of the segment '{seg.name}' does not match the external segment '{self.name}'.\n"
                f"  Expected {seg.bss_size}, got {self.bss_size}",
                status="warn",
            )
            ret = False
        if self.exclusive_ram_id != seg.exclusive_ram_id:
            log.write(
                f"Error: The exclusive_ram_id of the segment '{seg.name}' does not match the external segment '{self.name}'.\n"
                f"  Expected {seg.exclusive_ram_id}, got {self.exclusive_ram_id}",
                status="warn",
            )
            ret = False
        return ret

    def __repr__(self) -> str:
        # Shows a nicer string on the debugging screen
        return f"{self.name} (Rom: 0x{self.rom_start:08X} ~ 0x{self.rom_end:08X}, Vram: 0x{self.vram_start:08X} ~ 0x{self.vram_end:08X})"
