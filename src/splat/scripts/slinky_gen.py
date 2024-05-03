#! /usr/bin/env python3

import argparse
from pathlib import Path
from typing import List, Optional

from . import split
from ..util import options
from ..segtypes.segment import Segment
from ..segtypes.common.group import CommonSegGroup
from ..segtypes.common.data import CommonSegData
from ..segtypes.common.pad import CommonSegPad
from ..segtypes.n64.linker_offset import N64SegLinker_offset


def main(
    config_path: List[str],
    output: Optional[Path],
):
    config = split.initialize_config(config_path, None, False, False)

    # We depend on auto_all_sections doing its thing
    if ".data" not in options.opts.auto_all_sections:
        options.opts.auto_all_sections.insert(0, ".data")

    assert not options.opts.ld_legacy_generation, "Legacy linker script generation is not supported yet"

    out: List[str] = []

    all_segments = split.initialize_segments(config["segments"])

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

        base_section_type = segment.section_order

        out.append(f"    files:")
        if isinstance(segment, CommonSegGroup):
            files: List[Segment] = []
            if len(segment.subsegments) == 1:
                print("   ", segment.subsegments[0])
                files = [segment.subsegments[0]]
            else:
                for sub in segment.subsegments:
                    print("   ", sub)
                    if isinstance(sub, (CommonSegPad, N64SegLinker_offset)):
                        files.append(sub)
                    elif sub.get_linker_section_order() == base_section_type[0]:
                        files.append(sub)
                    else:
                        found = False
                        for i, aux_file in enumerate(files[::-1]):
                            if aux_file.name == sub.name:
                                found = True
                                if not sub.type.startswith("."):
                                    files.insert(len(files)-i, sub)
                                break

                        if not found:
                            files.append(sub)

            prev_file: Optional[Segment] = None
            for file in files:
                if isinstance(file, CommonSegPad):
                    assert prev_file is not None
                    out.append(f"      - {{ kind: pad, pad_amount: 0x{file.size:X}, section: {prev_file.get_linker_section_order()} }}")
                elif isinstance(file, N64SegLinker_offset):
                    assert prev_file is not None
                    out.append(f"      - {{ kind: linker_offset, linker_offset_name: {file.name}, section: {prev_file.get_linker_section_order()} }}")
                else:
                    for x in file.get_linker_entries():
                        out.append(f"      - {{ path: {x.object_path} }}")
                prev_file = file
        else:
            for x in segment.get_linker_entries():
                out.append(f"      - {{ path: {x.object_path} }}")

        out.append("")
        prev_seg = segment

    if output is None:
        print()
        for l in out:
            print(l)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("\n".join(out))


def add_arguments_to_parser(parser: argparse.ArgumentParser):
    parser.add_argument(
        "config", help="path to a compatible config .yaml file", nargs="+"
    )
    parser.add_argument(
        "-o", "--output", help="Output path. If missing the generated yaml will be printed to stdout", type=Path
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
