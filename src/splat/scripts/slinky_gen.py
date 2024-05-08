#! /usr/bin/env python3

import argparse
from pathlib import Path
from typing import Optional, List, Tuple, Dict

from . import split
from ..util import options
from ..segtypes.segment import Segment
from ..segtypes.common.group import CommonSegGroup

# from ..segtypes.common.data import CommonSegData
from ..segtypes.common.pad import CommonSegPad
from ..segtypes.n64.linker_offset import N64SegLinker_offset


def get_alloc_noload_sections(section_order: List[str]) -> Tuple[List[str], List[str]]:
    alloc_sections: List[str] = []
    noload_sections: List[str] = []

    if not options.opts.ld_bss_is_noload:
        alloc_sections.extend(section_order)
    else:
        i = 0
        for x in section_order:
            # If we see any of them lets assume the rest are noload
            # TODO: try to not hardcode them
            if x in {".sbss", ".scommon", ".bss", "COMMON", ".vubss"}:
                break
            alloc_sections.append(x)
            i += 1

        for x in section_order[i:]:
            noload_sections.append(x)

    return alloc_sections, noload_sections


def add_settings(out: List[str]):
    out.append("settings:")
    out.append(f"  # base_path: {options.opts.build_path}")
    out.append(f"  linker_symbols_style: {options.opts.segment_symbols_style}")
    if options.opts.elf_path:
        out.append(f"  target_path: {options.opts.elf_path}")
    if options.opts.ld_dependencies:
        out.append(f"  d_path: {options.opts.ld_script_path.with_suffix('.d')}")

    if options.opts.ld_symbol_header_path is not None:
        out.append(f"  symbols_header_path: {options.opts.ld_symbol_header_path}")
        out.append(f"  symbols_header_type: Addr")
        out.append(f"  symbols_header_as_array: False")

    if ".shstrtab" in options.opts.ld_sections_allowlist:
        options.opts.ld_sections_allowlist.remove(".shstrtab")
    if options.opts.ld_sections_allowlist:
        out.append(f"  sections_allowlist:")
        for x in options.opts.ld_sections_allowlist:
            out.append(f"    - {x}")

    if options.opts.ld_sections_denylist:
        out.append(f"  sections_denylist:")
        for x in options.opts.ld_sections_denylist:
            out.append(f"    - {x}")

    out.append(f"  discard_wildcard_section: {options.opts.ld_discard_section}")

    if options.opts.ld_partial_scripts_path is not None:
        out.append(f"  partial_scripts_folder: {options.opts.ld_partial_scripts_path}")
    if options.opts.ld_partial_build_segments_path is not None:
        out.append(
            f"  partial_build_segments_folder: {options.opts.ld_partial_build_segments_path}"
        )

    alloc_sections, noload_sections = get_alloc_noload_sections(
        options.opts.section_order
    )
    if len(alloc_sections) == 0:
        out.append(f"  alloc_sections: []")
    else:
        out.append(f"  alloc_sections:")
        for x in alloc_sections:
            out.append(f"    - {x}")

    if len(noload_sections) == 0:
        out.append(f"  noload_sections: []")
    else:
        out.append(f"  noload_sections:")
        for x in noload_sections:
            out.append(f"    - {x}")

    if options.opts.subalign is not None:
        out.append(f"  subalign: 0x{options.opts.subalign:X}")
    else:
        out.append(f"  subalign: null")

    out.append(f"  wildcard_sections: {options.opts.ld_wildcard_sections}")

    if options.opts.gp is not None:
        out.append(f"  hardcoded_gp_value: 0x{options.opts.gp:08X}")

    out.append(f"")


def find_index_by_name(files: List[Tuple[Segment, str]], name: str) -> int:
    for i, (file, section) in enumerate(files[::-1]):
        if file.name == name:
            return len(files) - i - 1

    return len(files)


def get_files_from_subsegments(
    section_change_per_seg_name: Dict[str, Dict[str, str]],
    segment: CommonSegGroup,
    base_section_type: str,
) -> List[Tuple[Segment, str]]:
    files: List[Tuple[Segment, str]] = []

    names: set[str] = set()

    prev_sub: Optional[Segment] = None
    for i, sub in enumerate(segment.subsegments):
        print("   ", i, sub)

        if sub.get_linker_section_order() != sub.get_linker_section_linksection():
            if sub.name not in section_change_per_seg_name:
                section_change_per_seg_name[sub.name] = dict()
            section_change_per_seg_name[sub.name][
                sub.get_linker_section_linksection()
            ] = sub.get_linker_section_order()

        if isinstance(sub, CommonSegPad):
            # These are special, add them as-is
            assert prev_sub is not None
            files.append((sub, prev_sub.get_linker_section_order()))
        elif isinstance(sub, N64SegLinker_offset):
            # These are special, add them as-is
            assert prev_sub is not None
            files.append((sub, prev_sub.get_linker_section_order()))
        elif sub.get_linker_section_order() == base_section_type:
            # Get base files
            files.append((sub, sub.get_linker_section_order()))
            names.add(sub.name)

        prev_sub = sub

    started_sections: set[str] = {base_section_type}
    prev_sub = None
    for i, sub in enumerate(segment.subsegments):
        if isinstance(sub, CommonSegPad):
            pass
        elif isinstance(sub, N64SegLinker_offset):
            pass
        elif sub.get_linker_section_order() == base_section_type:
            pass

        elif sub.is_auto_all:
            pass

        elif sub.name in names and sub.type.startswith("."):
            # Non-base file has been migrated to C file
            started_sections.add(sub.get_linker_section_order())

        else:
            # Look for any file that doesn't have a corresponding base file
            print("   ", i, sub)

            # Where to insert it?

            next_sub = (
                segment.subsegments[i + 1] if i + 1 < len(segment.subsegments) else None
            )

            # Check prev subsegment
            if (
                prev_sub is not None
                and prev_sub.name in names
                and prev_sub.get_linker_section_order()
                == sub.get_linker_section_order()
            ):
                prev_index = find_index_by_name(files, prev_sub.name)

                prev_file = files[prev_index][0] if prev_index < len(files) else None
                next_file = (
                    files[prev_index + 1][0] if prev_index + 1 < len(files) else None
                )

                print(
                    f"        Inserting '{sub}' into {prev_index+1}. Between '{prev_file}' and '{next_file}', guided by <prev> '{prev_sub}'"
                )
                files.insert(prev_index + 1, (sub, sub.get_linker_section_order()))
                names.add(sub.name)
                started_sections.add(sub.get_linker_section_order())
            elif sub.get_linker_section_order() not in started_sections:
                # new section, inserting it at the beginning should be harmless
                next_file = files[1][0] if 1 < len(files) else None
                print(f"        Inserting '{sub}' into {0}. Before '{next_file}'")
                files.insert(0, (sub, sub.get_linker_section_order()))
                names.add(sub.name)
                started_sections.add(sub.get_linker_section_order())
            elif next_sub is not None and next_sub.name in names:
                next_index = find_index_by_name(files, next_sub.name)

                prev_file = files[next_index - 1][0] if next_index - 1 > 0 else None
                next_file = files[next_index][0] if next_index < len(files) else None

                print(
                    f"        Inserting '{sub}' into {next_index}. Between '{prev_file}' and '{next_file}', guided by <next> '{next_sub}'"
                )
                files.insert(next_index, (sub, sub.get_linker_section_order()))
                names.add(sub.name)
                started_sections.add(sub.get_linker_section_order())
            else:
                # print(f"        '{sub}' has been dropped and forgotten. Sad :c")

                print(f"        Appending '{sub}' at the end of the list.")
                files.append((sub, sub.get_linker_section_order()))
                names.add(sub.name)
                started_sections.add(sub.get_linker_section_order())

        prev_sub = sub

    return files


def handle_group_segment(out: List[str], segment: CommonSegGroup):
    files: List[Tuple[Segment, str]] = []
    section_change_per_seg_name: Dict[str, Dict[str, str]] = dict()

    base_section_type = ".text"
    if segment.section_order.index(".rodata") < segment.section_order.index(".text"):
        base_section_type = ".rodata"

    if len(segment.subsegments) == 1:
        print("   ", segment.subsegments[0])
        files = [(segment.subsegments[0], "")]
    else:
        files = get_files_from_subsegments(
            section_change_per_seg_name, segment, base_section_type
        )

    for file, section in files:
        if isinstance(file, CommonSegPad):
            out.append(
                f"      - {{ kind: pad, pad_amount: 0x{file.size:X}, section: {section} }}"
            )
        elif isinstance(file, N64SegLinker_offset):
            out.append(
                f"      - {{ kind: linker_offset, linker_offset_name: {file.name}, section: {section} }}"
            )
        else:
            for linker_entries in file.get_linker_entries():
                if file.name in section_change_per_seg_name:
                    section_order = []
                    for k, v in section_change_per_seg_name[file.name].items():
                        section_order.append(f"{k}: {v}")
                    out.append(
                        f"      - {{ path: {linker_entries.object_path}, section_order: {{ {', '.join(section_order)} }} }}"
                    )
                else:
                    out.append(f"      - {{ path: {linker_entries.object_path} }}")


def add_segments(out: List[str], all_segments: List[Segment]):
    out.append("segments:")

    prev_seg: Optional[Segment] = None
    for segment in all_segments:
        print(segment)
        name = segment.name.replace("/", "_")
        if name[0] in "0123456789":
            name = "_" + name
        out.append(f"  - name: {name}")

        if segment.vram_class is not None:
            out.append(f"    vram_class: {segment.vram_class.name}")
        elif segment.given_follows_vram is not None:
            if prev_seg is not None and segment.given_follows_vram != prev_seg.name:
                out.append(f"    follows_segment: {segment.given_follows_vram}")
        elif segment.vram_symbol is not None:
            out.append(f"    fixed_symbol: {segment.vram_symbol}")
        elif segment.vram_start is not None:
            out.append(f"    fixed_vram: 0x{segment.vram_start:08X}")

        if segment.subalign != options.opts.subalign:
            if segment.subalign is not None:
                out.append(f"    subalign: 0x{segment.subalign:X}")
            else:
                out.append(f"    subalign: null")

        if (
            options.opts.segment_end_before_align
            and prev_seg is not None
            and prev_seg.align is not None
        ):
            out.append(f"    segment_start_align: 0x{prev_seg.align:X}")
        else:
            out.append(f"    segment_start_align: null")

        if segment.align is not None and options.opts.ld_align_section_vram_end:
            out.append(f"    section_end_align: 0x{segment.align:X}")
        else:
            out.append(f"    section_end_align: null")

        if segment.section_order != options.opts.section_order:
            alloc_sections, noload_sections = get_alloc_noload_sections(
                segment.section_order
            )
            if len(alloc_sections) == 0:
                out.append(f"    alloc_sections: []")
            else:
                out.append(f"    alloc_sections:")
                for x in alloc_sections:
                    out.append(f"      - {x}")

            if len(noload_sections) == 0:
                out.append(f"    noload_sections: []")
            else:
                out.append(f"    noload_sections:")
                for x in noload_sections:
                    out.append(f"      - {x}")

        out.append(f"    files:")
        if isinstance(segment, CommonSegGroup):
            handle_group_segment(out, segment)
        else:
            for linker_entries in segment.get_linker_entries():
                out.append(f"      - {{ path: {linker_entries.object_path} }}")

        out.append("")
        prev_seg = segment


def write_out(out: List[str], output: Optional[Path]):
    if output is None:
        print()
        for l in out:
            print(l)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("\n".join(out))


def main(
    config_path: List[str],
    output: Optional[Path],
):
    config = split.initialize_config(config_path, None, False, False)

    # We depend on auto_all_sections doing its thing
    if ".data" not in options.opts.auto_all_sections:
        options.opts.auto_all_sections.insert(0, ".data")

    assert (
        not options.opts.ld_legacy_generation
    ), "Legacy linker script generation is not supported yet"

    all_segments = split.initialize_segments(config["segments"])

    out: List[str] = []

    add_settings(out)
    add_segments(out, all_segments)

    write_out(out, output)


def add_arguments_to_parser(parser: argparse.ArgumentParser):
    parser.add_argument(
        "config", help="path to a compatible config .yaml file", nargs="+"
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output path. If missing the generated yaml will be printed to stdout",
        type=Path,
    )


def process_arguments(args: argparse.Namespace):
    main(
        args.config,
        args.output,
    )


script_description = "Generate a slinky yaml from a splat yaml"


def add_subparser(subparser: argparse._SubParsersAction):
    parser = subparser.add_parser(
        "slinky_gen", help=script_description, description=script_description
    )
    add_arguments_to_parser(parser)
    parser.set_defaults(func=process_arguments)


parser = argparse.ArgumentParser(description=script_description)
add_arguments_to_parser(parser)

if __name__ == "__main__":
    args = parser.parse_args()
    process_arguments(args)
