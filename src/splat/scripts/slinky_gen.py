#! /usr/bin/env python3

import argparse
from pathlib import Path
from typing import List, Optional

from . import split
from ..util import options
from ..segtypes.common.group import CommonSegGroup
from ..segtypes.common.data import CommonSegData


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

    for segment in all_segments:
        print(segment)
        name = segment.name
        if name[0] in "0123456789":
            name = "_" + name
        out.append(f"  - name: {name}")

        out.append(f"    files:")
        if isinstance(segment, CommonSegGroup):
            for sub in segment.subsegments:
                print("   ", sub)
                if sub.get_linker_section_order() == ".data":
                    for x in sub.get_linker_entries():
                        out.append(f"      - {{ path: {x.object_path} }}")
        else:
            for x in segment.get_linker_entries():
                out.append(f"      - {{ path: {x.object_path} }}")

        out.append("")

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
