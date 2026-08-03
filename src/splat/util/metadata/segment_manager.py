import dataclasses
from typing import Callable, Dict, Optional, Set, Tuple, TYPE_CHECKING, Union

from .segment_metadata import SegmentMetadata, SegmentKind
from .parent_segment_info import ParentSegmentInfo
from .overlay_metadata import OverlayMetadata

from ..symbols import Symbol
from .. import log, options

# circular import
if TYPE_CHECKING:
    from ...segtypes.segment import Segment
    from ..external_segment import ExternalSegment


class SegmentManager:
    """
    Grouping for all segment metadatas.
    """

    def __init__(self) -> None:
        # User-declared symbols that do not belong to any other segment.
        self.absolute_segment: SegmentMetadata = SegmentMetadata(
            SegmentKind.Absolute,
            "$absolute",
            0x0,
            0x0,
            0x00000000,
            0xFFFFFFFF,
            prioritized_segments=[],
            exclusive_ram_id=None,
            segment=None,
        )

        # Globally visible segments.
        # This kind have no address overlapping issues with any other segment.
        self.global_segments: list[SegmentMetadata] = []

        # Overlays.
        # This kind may have addresses overlapping between them.
        self.overlay_segments: dict[str, OverlayMetadata] = {}
        """key: exclusive_ram_id"""

        # Externally declared segments that were discarded.
        # Discarded because they overlap with the current global segment, this
        # happens because the current global segment corresponds to a PSX/PS2
        # binary overlay, so the other external segments may overlap with this.
        # These are discarded, so the symbols nor segments will be used when
        # looking for symbol references or creating automatically generated
        # symbols.
        self.discarded_external_segments: list[SegmentMetadata] = []

        # Dumpster for failed segment lookups.
        self.unknown_segment: SegmentMetadata = SegmentMetadata(
            SegmentKind.Unknown,
            "$unknown",
            0x0,
            0x0,
            0x00000000,
            0xFFFFFFFF,
            prioritized_segments=[],
            exclusive_ram_id=None,
            segment=None,
        )

        # ?
        self.all_symbols: list[Symbol] = []

        self.global_rom_start: Optional[int] = None
        self.global_rom_end: Optional[int] = None
        self.global_vram_start: Optional[int] = None
        self.global_vram_end: Optional[int] = None

    def find_owned_segment(self, info: ParentSegmentInfo) -> SegmentMetadata:
        """
        Find the segment metadata corresponding to the given segment parent info.
        """

        if info.exclusive_ram_id is not None:
            segments_per_rom = self.overlay_segments.get(info.exclusive_ram_id)
            if segments_per_rom is not None:
                owned_segment = segments_per_rom.segments.get(info.segment_rom)
                if owned_segment is not None:
                    return owned_segment
        else:
            for owned_segment in self.global_segments:
                if owned_segment.in_rom_range(info.segment_rom):
                    return owned_segment
                elif owned_segment.in_vram_range(info.segment_vram):
                    # Global segment doesn't have overlapping issues, so it should
                    # be fine to check for vram address.
                    # This can be required by segments that only have bss sections.
                    return owned_segment

        # log.write(f"Error: Unable to find an owned segment for {info=}.", status="warn")
        return self.unknown_segment

    def find_referenced_segment_for_creation(
        self,
        vram: int,
        info: ParentSegmentInfo,
    ) -> SegmentMetadata:
        """
        Find a segment where a symbol with the given address could be created.

        This may return the corresponding owned segment if the vram address
        corresponds to the segment, or a prioritized segment for the owned
        segment that fits the given vram address. Global segments are always
        checked, even if they aren't prioritized or owned.
        """

        # First, check the global segments.
        # Overlays shouldn't overlap with the global segments, so this should be fine.
        for seg in self.global_segments:
            if seg.in_vram_range(vram):
                return seg
            if seg.rom_start == info.segment_rom:
                segment = self._find_prioritized_segment(vram, seg)
                if segment is not None:
                    return segment

        # Look up in overlays
        if len(self.overlay_segments) > 0:
            overlay_segment = self._find_referenced_overlay_segment_for_creation(
                vram,
                info,
            )
            if overlay_segment is not None:
                return overlay_segment

        # Fallback to the unknown segment
        return self.unknown_segment

    def _find_referenced_overlay_segment_for_creation(
        self,
        vram: int,
        info: ParentSegmentInfo,
    ) -> Optional[SegmentMetadata]:
        # If the parent info has no exclusive_ram_id, then it is a global segment,
        # meaning it shouldn't be referencing an overlay symbol by default.
        if info.exclusive_ram_id is None:
            return None

        # Check the segment corresponding to this specific overlay.
        segments_per_rom = self.overlay_segments.get(info.exclusive_ram_id)
        if segments_per_rom is not None:
            owned_segment = segments_per_rom.segments.get(info.segment_rom)
            if owned_segment is not None:
                if owned_segment.in_vram_range(vram):
                    return owned_segment

                # Check for any prioiritised overlay, if any.
                segment = self._find_prioritized_segment(vram, owned_segment)
                if segment is not None:
                    return segment

        # Don't check other overlay segments here!
        # We don't have a way to know what segment this overlay is referencing,
        # picking an arbitrary one for symbol creation will lead to nasty bugs.

        return None

    def _find_prioritized_segment(
        self,
        vram: int,
        owned_segment: SegmentMetadata,
    ) -> Optional[SegmentMetadata]:
        """
        Find a prioritized segment that fits the given vram.
        """
        for prioritized_segment in owned_segment.get_prioritized_segments():
            for segments_per_rom in self.overlay_segments.values():
                if not segments_per_rom.in_vram_range(vram):
                    continue
                for segment in segments_per_rom.segments.values():
                    if segment.name == prioritized_segment and segment.in_vram_range(
                        vram
                    ):
                        return segment
        return None

    def find_symbol_from_any_segment(
        self,
        vram: int,
        info: ParentSegmentInfo,
        allow_addend: bool,
        validate: Callable[[Symbol], bool],
    ) -> Optional[Symbol]:
        """
        Check all segments looking for a symbol matching the given address.

        Applies visibility rules based on the segment for `info`.

        The symbol will be checked against the `validate` callback,
        if the callback returns `False` then the next segment will be checked
        and so on.
        """

        # Absolute symbols first.
        sym = self.absolute_segment.find_symbol(vram, allow_addend)
        if sym is not None:
            return sym

        # Global segments second.
        for seg in self.global_segments:
            if seg.in_vram_range(vram):
                # If we find this vram is within a global segment then we can stop
                # searching, because we know this should be the only segment that
                # should overlap this segment.
                sym = seg.find_symbol(vram, allow_addend)
                if sym is not None and validate(sym):
                    return sym
                return None
            if seg.rom_start == info.segment_rom:
                # Check for prioritized segments, if any.
                sym = self._find_symbol_from_prioritized_segments(
                    vram,
                    allow_addend,
                    seg,
                    validate,
                )
                if sym is not None:
                    return sym

        # Overlays third
        if len(self.overlay_segments) > 0:
            sym = self._find_symbol_from_overlay_segments(
                vram,
                info,
                allow_addend,
                validate,
            )
            if sym is not None:
                return sym

        # Lastly the dumpster
        sym = self.unknown_segment.find_symbol(vram, allow_addend)
        if sym is not None and validate(sym):
            return sym
        return None

    def _find_symbol_from_overlay_segments(
        self,
        vram: int,
        info: ParentSegmentInfo,
        allow_addend: bool,
        validate: Callable[[Symbol], bool],
    ) -> Optional[Symbol]:
        exclusive_ram_id = info.exclusive_ram_id

        # First, look up for the segment associated to this exclusive_ram_id
        # which matches the rom address of the parent segment so we can
        # prioritize it.
        if exclusive_ram_id is not None:
            segments_per_rom = self.overlay_segments.get(exclusive_ram_id)
            if segments_per_rom is not None:
                owned_segment = segments_per_rom.segments.get(info.segment_rom)
                if owned_segment is not None:
                    if owned_segment.in_vram_range(vram):
                        sym = owned_segment.find_symbol(vram, allow_addend)
                        if sym is not None and validate(sym):
                            return sym
                        return None

                    # Check for prioritized segments, if any.
                    sym = self._find_symbol_from_prioritized_segments(
                        vram,
                        allow_addend,
                        owned_segment,
                        validate,
                    )
                    if sym is not None:
                        return sym

        # If not found, then we should check every exclusive_ram_id except the
        # one associated with the parent segment.

        # First, we look for exclusive_ram_id that contain a single segment.
        # This way is less likely we grab the wrong symbol.
        for ovl_id, segments_per_rom in self.overlay_segments.items():
            if exclusive_ram_id == ovl_id:
                continue
            if not segments_per_rom.in_vram_range(vram):
                continue

            if len(segments_per_rom.segments) != 1:
                continue

            for segment in segments_per_rom.segments.values():
                if segment.in_vram_range(vram):
                    sym = segment.find_symbol(vram, allow_addend)
                    if sym is not None and validate(sym):
                        return sym

        # if we haven't found the symbol yet, then just look up everywhere else.
        for ovl_id, segments_per_rom in self.overlay_segments.items():
            if exclusive_ram_id == ovl_id:
                continue
            if not segments_per_rom.in_vram_range(vram):
                continue

            if len(segments_per_rom.segments) == 1:
                continue

            for segment in segments_per_rom.segments.values():
                if segment.in_vram_range(vram):
                    sym = segment.find_symbol(vram, allow_addend)
                    if sym is not None and validate(sym):
                        return sym

        return None

    def _find_symbol_from_prioritized_segments(
        self,
        vram: int,
        allow_addend: bool,
        owned_segment: SegmentMetadata,
        validate: Callable[[Symbol], bool],
    ) -> Optional[Symbol]:
        for prioritized_segment in owned_segment.get_prioritized_segments():
            for segments_per_rom in self.overlay_segments.values():
                if not segments_per_rom.in_vram_range(vram):
                    continue
                for segment in segments_per_rom.segments.values():
                    if segment.name == prioritized_segment and segment.in_vram_range(
                        vram
                    ):
                        sym = segment.find_symbol(vram, allow_addend)
                        if sym is not None and validate(sym):
                            return sym

        return None

    def _add_global_segment(
        self,
        name: str,
        rom_start: int,
        rom_end: int,
        vram_start: int,
        vram_end: int,
        prioritized_segments: list[str],
        segment: Optional["Segment"],
    ) -> SegmentMetadata:
        if self.global_rom_start is None or rom_start < self.global_rom_start:
            self.global_rom_start = rom_start
        if self.global_rom_end is None or self.global_rom_end < rom_end:
            self.global_rom_end = rom_end
        if self.global_vram_start is None or vram_start < self.global_vram_start:
            self.global_vram_start = vram_start
        if self.global_vram_end is None or self.global_vram_end < vram_end:
            self.global_vram_end = vram_end

        seg_meta = SegmentMetadata(
            SegmentKind.Global,
            name,
            rom_start,
            rom_end,
            vram_start,
            vram_end,
            prioritized_segments,
            None,
            segment,
        )
        self.global_segments.append(seg_meta)
        return seg_meta

    def _add_overlay_segment(
        self,
        exclusive_ram_id: str,
        name: str,
        rom_start: int,
        rom_end: int,
        vram_start: int,
        vram_end: int,
        prioritized_segments: list[str],
        segment: Optional["Segment"],
    ) -> SegmentMetadata:
        ovl_meta = self.overlay_segments.setdefault(
            exclusive_ram_id,
            OverlayMetadata(
                exclusive_ram_id,
                rom_start,
                rom_end,
                vram_start,
                vram_end,
                {},
            ),
        )
        return ovl_meta.add_segment(
            name,
            rom_start,
            rom_end,
            vram_start,
            vram_end,
            prioritized_segments,
            segment,
        )

    def _add_discarded_external_segment(
        self,
        external_segment: "ExternalSegment",
    ) -> SegmentMetadata:
        seg_meta = SegmentMetadata(
            SegmentKind.Global if external_segment.is_global else SegmentKind.Overlay,
            external_segment.name,
            external_segment.rom_start,
            external_segment.rom_end,
            external_segment.vram_start,
            external_segment.vram_end,
            [],
            None,
            None,
        )
        self.discarded_external_segments.append(seg_meta)
        return seg_meta

    def _initialize_segments(
        self,
        all_segments: "list[Segment]",
        external_segments: "list[ExternalSegment]",
    ) -> Tuple[Dict[str, SegmentMetadata], Set[str]]:
        global_pack = AddressPack(
            vram_start=options.opts.global_vram_start,
            vram_end=options.opts.global_vram_end,
        )
        seen_global_pack = AddressPack()

        overlay_segments: list[SegmentMetadata] = []

        segments_by_name: Dict[str, SegmentMetadata] = {}
        skipped_segments: Set[str] = set()

        global_segments: list[Segment] = []
        global_segments_after_overlays: list[Segment] = []

        # Create all segments in the grouping
        for segment in all_segments:
            if (
                not isinstance(segment.vram_start, int)
                or not isinstance(segment.vram_end, int)
                or not isinstance(segment.rom_start, int)
                or not isinstance(segment.rom_end, int)
            ):
                skipped_segments.add(segment.name)
                continue

            ram_id = segment.get_exclusive_ram_id()
            if ram_id is None and segment.special_vram_segment:
                # Special segments which should not be accounted in the global VRAM calculation, like N64's IPL3
                ram_id = "$special_vram_segment"

            if ram_id is not None:
                # Overlay

                if segment.vram_start == segment.vram_end:
                    # Skip zero-sized segments.
                    continue

                seg_meta = self._add_overlay_segment(
                    ram_id,
                    segment.name,
                    segment.rom_start,
                    segment.rom_end,
                    segment.vram_start,
                    segment.vram_end,
                    segment.prioritized_segments,
                    segment,
                )
                segment.owned_metadata = seg_meta
                overlay_segments.append(seg_meta)
            else:
                # Global segment

                seg_meta = self._add_global_segment(
                    segment.name,
                    segment.rom_start,
                    segment.rom_end,
                    segment.vram_start,
                    segment.vram_end,
                    segment.prioritized_segments,
                    segment,
                )
                segment.owned_metadata = seg_meta
                global_segments.append(segment)

                global_pack.update(
                    segment,
                    overlay_segments=overlay_segments,
                    global_segments_after_overlays=global_segments_after_overlays,
                )
                seen_global_pack.update(segment)

            segments_by_name[seg_meta.name] = seg_meta

        for ext_segment in external_segments:
            # Create metadata for external segments.
            # These only declare the segments from other binaries.

            if ext_segment.name in segments_by_name:
                # The segments from the current binary should be listed as an
                # external segment too, but we don't want to create a
                # duplicated metadata for it.
                continue

            if ext_segment.is_global:
                # Global segment

                seg_meta = self._add_global_segment(
                    ext_segment.name,
                    ext_segment.rom_start,
                    ext_segment.rom_end,
                    ext_segment.vram_start,
                    ext_segment.vram_end,
                    [],
                    None,
                )

                global_pack.update(
                    ext_segment,
                    overlay_segments=overlay_segments,
                    global_segments_after_overlays=global_segments_after_overlays,
                )
                seen_global_pack.update(ext_segment)
            else:
                # Overlay

                if ext_segment.vram_start == ext_segment.vram_end:
                    # Skip zero-sized segments.
                    continue

                if global_pack.overlaps_vram(
                    ext_segment.vram_start,
                    ext_segment.vram_end,
                ):
                    # This external segment overlaps with the current global
                    # segment very likely because the current binary being
                    # splitted is a PSX/PS2 standalone overlay binary.
                    # There's no point on tracking this segment when trying to
                    # look for address references or other stuff, so we just
                    # discard it and do nothing with it.
                    # We still need to create it and know about it existence in
                    # case the user declared a symbol referencing this segment
                    # in the symbol_addrs file.
                    seg_meta = self._add_discarded_external_segment(ext_segment)
                else:
                    ram_id = ext_segment.exclusive_ram_id or ext_segment.name
                    seg_meta = self._add_overlay_segment(
                        ram_id,
                        ext_segment.name,
                        ext_segment.rom_start,
                        ext_segment.rom_end,
                        ext_segment.vram_start,
                        ext_segment.vram_end,
                        [],
                        None,
                    )
                    overlay_segments.append(seg_meta)
            segments_by_name[seg_meta.name] = seg_meta

        if (
            global_pack.vram_start is not None
            and global_pack.vram_end is not None
            and global_pack.rom_start is not None
            and global_pack.rom_end is not None
        ):
            # Create extra global segments in case they are needed
            if (
                seen_global_pack.vram_start is not None
                and seen_global_pack.vram_end is not None
                and seen_global_pack.rom_start is not None
                and seen_global_pack.rom_end is not None
            ):
                # Account for options.opts.global_vram_start and options.opts.global_vram_end for PSX and PSP
                if global_pack.vram_start < seen_global_pack.vram_start:
                    rom_start = (
                        seen_global_pack.rom_start
                        + global_pack.vram_start
                        - seen_global_pack.vram_start
                    )
                    seg_meta = self._add_global_segment(
                        "$global_left",
                        rom_start,
                        seen_global_pack.rom_start,
                        global_pack.vram_start,
                        seen_global_pack.vram_start,
                        [],
                        None,
                    )
                    segments_by_name[seg_meta.name] = seg_meta
                if global_pack.vram_end > seen_global_pack.vram_end:
                    rom_end = (
                        seen_global_pack.rom_end
                        + global_pack.vram_end
                        - seen_global_pack.vram_end
                    )
                    seg_meta = self._add_global_segment(
                        "$global_right",
                        seen_global_pack.rom_end,
                        rom_end,
                        seen_global_pack.vram_end,
                        global_pack.vram_end,
                        [],
                        None,
                    )
                    segments_by_name[seg_meta.name] = seg_meta

            # Validation

            overlaps_found = False
            # Check the vram range of the global segment does not overlap with any overlay segment
            for ovl_segment in overlay_segments:
                assert ovl_segment.vram_start <= ovl_segment.vram_end, (
                    f"{ovl_segment.vram_start:08X} {ovl_segment.vram_end:08X}"
                )
                if global_pack.overlaps_vram(
                    ovl_segment.vram_start,
                    ovl_segment.vram_end,
                ):
                    log.write(
                        f"Error: Overlay segment {ovl_segment.name} with vram range ([0x{ovl_segment.vram_start:08X}, 0x{ovl_segment.vram_end:08X}]) of the non-global segment at rom address 0x{ovl_segment.rom_start:X} overlaps with the global vram range ([0x{global_pack.vram_start:08X}, 0x{global_pack.vram_end:08X}])",
                        status="warn",
                    )
                    overlaps_found = True
            if overlaps_found:
                log.write(
                    "Overlaps between non-global and global segments were found.\n"
                    "This is usually caused by missing `exclusive_ram_id` tags on segments that have a higher vram address than other `exclusive_ram_id`-tagged segments"
                )
                if len(global_segments) > 0:
                    log.write(
                        "These are all the global segments:",
                        status="warn",
                    )
                    for seg in global_segments_after_overlays:
                        log.write(
                            f"    '{seg.name}', rom: 0x{seg.rom_start:06X}, vram: 0x{seg.vram_start:08X}"
                        )

                if global_pack.segment_largest_vram is not None:
                    log.write(
                        f"The global segment with the largest vram seen is {global_pack.segment_largest_vram}. Rom: 0x{global_pack.segment_largest_vram.rom_start:X}, Vram: 0x{global_pack.segment_largest_vram.vram_start:08X}"
                    )

                if len(global_segments_after_overlays) > 0:
                    log.write(
                        "These segments are the main suspects for missing a `exclusive_ram_id` tag:",
                        status="warn",
                    )
                    for seg in global_segments_after_overlays:
                        log.write(
                            f"    '{seg.name}', rom: 0x{seg.rom_start:06X}, vram: 0x{seg.vram_start:08X}"
                        )
                else:
                    log.write("No suspected segments??", status="warn")
                log.error("Stopping due to the above errors")

        return segments_by_name, skipped_segments

    def _initialize_symbols(
        self,
        all_symbols: "list[Symbol]",
        segments_by_name: Dict[str, SegmentMetadata],
        skipped_segments: Set[str],
    ) -> None:
        # Pass every symbol to its corresponding segment.
        lost_symbols = []
        for sym in all_symbols:
            # Absolute segment takes priority over everything
            if sym.absolute:
                self.absolute_segment.add_user_symbol(sym)
                continue

            # If the symbol is associated to an external segment then count it
            # as an absolute symbol to ensure global segments can reference it.
            ext_seg = sym.external_segment
            if ext_seg is not None:
                # Since we are flattening symbols from multiple external
                # segments into the absolute segment then it is likely for them
                # to overlap, in that case keep the first seen one and drop the
                # rest.
                self.absolute_segment.add_user_symbol(sym, _ensure_no_overlap=False)
                meta = segments_by_name.get(ext_seg.name)
                if meta is not None:
                    meta.add_user_symbol(sym)
                continue

            # Then look up for explicit associated segments.
            seg = sym.segment
            if seg is not None:
                meta = segments_by_name.get(seg.name)
                if meta is not None:
                    meta.add_user_symbol(sym)
                    continue
                elif seg.name in skipped_segments:
                    log.write(
                        f"Error: Unable to associated '{sym}' to segment '{seg}' because that segment is missing a vram/rom address.",
                        status="warn",
                    )
                else:
                    log.write(
                        f"Warning (Maybe bug): User-declared symbol '{sym}' is associated to non existing segment '{seg}'.\n"
                        "  This is an issue because unexpected segments should have been filtered on a previous step.\n"
                        "  Please report.",
                        status="warn",
                    )

            # Then try to look up for global segments.
            found_global = False
            for meta_seg in self.global_segments:
                if meta_seg.in_vram_range(sym.vram_start):
                    meta_seg.add_user_symbol(sym)
                    found_global = True
                    break
            if found_global:
                continue

            # We run out of places to put this symbol into.
            # We need the user to give us more info on what to do with this.
            possible_segments = [
                f"{seg_meta.name} (Vram: 0x{seg_meta.vram_start:08X}, Rom: 0x{seg_meta.rom_start:X})"
                for seg_meta in segments_by_name.values()
                if seg_meta.in_vram_range(sym.vram_start)
            ]
            possible_segments_str = (
                f"[{', '.join(possible_segments)}]"
                if len(possible_segments) > 0
                else "None"
            )
            lost_symbols.append(
                f"{sym.name} (Vram: 0x{sym.vram_start:08X}). Suspected segments: {possible_segments_str}"
            )
            self.unknown_segment.add_user_symbol(sym)

        if len(lost_symbols) > 0:
            log.write(
                "\nError: Unable to determine a segment for the following user-declared symbols.\n"
                "  Try specifying the segment they belong to with 'segment:segment_name' in your symbol_addrs file.\n"
                "  If the address of this symbol is not part of any segment, or if you believe this symbol should be\n"
                "  globally visible and take priority over other symbol references then use the `absolute:True`\n"
                "  user attribute instead.",
                status="warn",
            )
            log.write("    " + "\n    ".join(lost_symbols))
            log.write("\n")
            # TODO: uncomment on a future version
            # log.error("Stopping due to the above issues.")

        self.all_symbols = all_symbols


@dataclasses.dataclass
class AddressPack:
    """
    Helper class to help track the boundaries of global segments.
    """

    rom_start: Optional[int] = None
    rom_end: Optional[int] = None
    vram_start: Optional[int] = None
    vram_end: Optional[int] = None
    segment_largest_vram: Optional["Segment"] = None

    def update(
        self,
        segment: Union["Segment", "ExternalSegment"],
        *,
        overlay_segments: Optional[list[SegmentMetadata]] = None,
        global_segments_after_overlays: Optional[list["Segment"]] = None,
    ) -> None:
        from ...segtypes.segment import Segment

        if (
            segment.rom_start is None
            or segment.rom_end is None
            or segment.vram_start is None
            or segment.vram_end is None
        ):
            return

        if self.rom_start is None or segment.rom_start < self.rom_start:
            self.rom_start = segment.rom_start

        if self.rom_end is None or self.rom_end < segment.rom_end:
            self.rom_end = segment.rom_end

        if self.vram_start is None or segment.vram_start < self.vram_start:
            self.vram_start = segment.vram_start

        largest = False
        largest_override = False
        if self.vram_end is None:
            self.vram_end = segment.vram_end
            largest = True
        elif self.vram_end < segment.vram_end:
            self.vram_end = segment.vram_end
            largest = True
            largest_override = True

        if isinstance(segment, Segment):
            if largest:
                self.segment_largest_vram = segment
                if largest_override:
                    if (
                        overlay_segments is not None
                        and global_segments_after_overlays is not None
                    ):
                        if len(overlay_segments) > 0:
                            # Global segment *after* overlay segments?
                            global_segments_after_overlays.append(segment)

    def overlaps_vram(self, vram_start: int, vram_end: int) -> bool:
        if self.vram_start is None or self.vram_end is None:
            return False
        if vram_end > self.vram_start and self.vram_end > vram_start:
            return True
        return False


manager = SegmentManager()


def initialize(
    all_segments: "list[Segment]",
    all_symbols: "list[Symbol]",
    external_segments: "Optional[list[ExternalSegment]]" = None,
) -> None:
    global manager
    segments_by_name, skipped_segments = manager._initialize_segments(
        all_segments, external_segments or []
    )
    manager._initialize_symbols(all_symbols, segments_by_name, skipped_segments)


def reset() -> None:
    global manager
    manager = SegmentManager()
