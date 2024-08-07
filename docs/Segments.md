# Segments

The configuration file for **splat** consists of a number of well-defined segments.

Most segments can be defined as a either a dictionary or a list, however the list syntax is only suitable for simple cases as it does not allow for specifying many of the options a segment type has to offer.

Splat segments' behavior generally falls under two categories: extraction and linking. Some segments will only do extraction, some will only do linking, some both, and some neither. Generally, segments will describe both extraction and linking behavior. Additionally, a segment type whose name starts with a dot (.) will only focus on linking.

## `asm`

**Description:**

Segments designated Assembly, `asm`, will be disassembled via [spimdisasm](https://github.com/Decompollaborate/spimdisasm) and enriched with Symbols based on the contents of the `symbol_addrs` configuration.

**Example:**

```yaml
# as list
- [0xABC, asm, filepath1]
- [0xABC, asm, dir1/filepath2]  # this will create filepath2.s inside a directory named dir1

# as dictionary
- name: filepath
  type: asm
  start: 0xABC
```

### `hasm`

**Description:**

Hand-written Assembly, `hasm`, similar to `asm` except it will not overwrite any existing files. Useful when assembly has been manually edited.

**Example:**

```yaml
# as list
- [0xABC, hasm, filepath]

# as dictionary
- name: filepath
  type: hasm
  start: 0xABC
```

## `bin`

**Description:**

The `bin`(ary) segment type is for raw data, or data where the type is yet to be determined, data will be written out as raw `.bin` files.

**Example:**

```yaml
# as list
- [0xABC, bin, filepath]

# as dictionary
- name: filepath
  type: bin
  start: 0xABC
```

## `code`

**Description:**

The 'code' segment type, `code` is a group that can have many `subsegments`. Useful to group sections of code together (e.g. all files part of the same overlay).

**Example:**

```yaml
# must be a dictionary
- name:  main
  type:  code
  start: 0x00001000
  vram:  0x80125900
  subsegments:
    - [0x1000, asm, entrypoint]
    - [0x1050, c, main]
```

## `c`

**Description:**

The C code segments have two behaviors:

- If the target `.c` file does not exist, a new file will be generated with macros to include the original assembly (macros differ for IDO vs GCC compiler).
- Otherwise the target `.c` file is scanned to determine what assembly needs to be extracted from the ROM.

Assembly that is extracted due to a `c` segment will be written to a `nonmatchings` folder, with one function per file.

**Example:**

```yaml
# as list
- [0xABC, c, filepath]

# as dictionary
- name: filepath
  type: c
  start: 0xABC
```

## `header`

**Description:**

This is platform specific; parses the data and interprets as a header for e.g. N64 or PS1 elf.

**Example:**

```yaml
# as list
- [0xABC, header, filepath]

# as dictionary
- name: filepath
  type: header
  start: 0xABC
```

## `data`

**Description:**

Data located in the ROM. Extracted as assembly; integer, float and string types will be attempted to be inferred by the disassembler.

**Example:**

```yaml
# as list
- [0xABC, data, filepath]

# as dictionary
- name: filepath
  type: data
  start: 0xABC
```

This will created `filepath.data.s` within the `asm` folder.

## `.data`

**Description:**

Data located in the ROM that is linked from a C file. Use the `.data` segment to tell the linker to pull the `.data` section from the compiled object of corresponding `c` segment.

**Example:**

```yaml
# as list
- [0xABC, .data, filepath]

# as dictionary
- name: filepath
  type: .data
  start: 0xABC
```

**NOTE:** `splat` will not generate any `.data.s` files for these `.` (dot) sections.

## `rodata`

**Description:**

Read-only data located in the ROM, e.g. floats, strings and jump tables. Extracted as assembly; integer, float and string types will be attempted to be inferred by the disassembler.

**Example:**

```yaml
# as list
- [0xABC, rodata, filepath]

# as dictionary
- name: filepath
  type: rodata
  start: 0xABC
```

This will created `filepath.rodata.s` within the `asm` folder.

## `.rodata`

**Description:**

Read-only data located in the ROM, linked to a C file. Use the `.rodata` segment to tell the linker to pull the `.rodata` section from the compiled object of corresponding `c` segment.

**Example:**

```yaml
# as list
- [0xABC, .rodata, filepath]

# as dictionary
- name: filepath
  type: .rodata
  start: 0xABC
```

**NOTE:** `splat` will not generate any `.rodata.s` files for these `.` (dot) sections.

## `bss`

**Description:**

`bss` is where variables are placed that have been declared but are not given an initial value. These sections are usually discarded from the final binary (although PSX binaries seem to include them!).

Note that the `bss_size` option needs to be set at segment level for `bss` segments to work correctly.

**Example:**

```yaml
- { start: 0x7D1AD0, type: bss, name: filepath, vram: 0x803C0420 }
```

## `.bss`

**Description:**

Links the `.bss` section of the associated `c` file.

**Example:**

```yaml
- { start: 0x7D1AD0, type: .bss, name: filepath, vram: 0x803C0420 }
```

## Images

**Description:**

**splat** supports most of the [N64 image formats](https://n64squid.com/homebrew/n64-sdk/textures/image-formats/):

- `i`, i.e. `i4` and `i8`
- `ia`, i.e. `ia4`, `ia8`, and `ia16`
- `ci`, i.e. `ci4` and `ci8`
- `rgb`, i.e. `rgba32` and `rgba16`

These segments will parse the image data and dump out a `png` file.

**Note:** Using the dictionary syntax allows for richer configuration.

**Example:**

```yaml
# as list
- [0xABC, i4, filename, width, height]
# as a dictionary
- name: filename
  type: i4
  start: 0xABC
  width: 64
  height: 64
  flip_x: yes
  flip_y: no
```

`ci` (paletted) segments have a `palettes: []` setting that represents the list of palettes that should be linked to the `ci`. For each linked palette, an image will be exported. The implicit value of `palettes` is a one-element list containing the name of the raster, which means palettes and rasters with the same name will automatically be linked.

Palette segments can specify a `global_id`, which can be referred to from a `ci`'s `palettes` list. The `global_id` space is searched first, and this allows cross-segment links between palettes and rasters.

## `pad`

`pad` is a segment that represents a rom region that's filled with zeroes and decomping it doesn't have much value.

This segment does not generate an assembly (`.s`) or binary (`.bin`) file, it simply increments the position of the linker script, avoding to build zero-filled files.

While this kind of segment can be represented by other segment types ([`asm`](#asm), [`data`](#data), etc), it is better practice to use this segment instead to better reflect the contents of the file.

**Example:**

```yaml
- [0x00B250, pad, nops_00B250]
```

## incbins

incbin segments correpond to a family of segments used for extracting binary blobs.

Their main advantage over the [`bin`](#bin) segment is the incbins allows to specify a specific section type instead of defaulting to simply `.data`. This is done by generating an assembly file that uses the `.incbin` asm directive to include the binary blob.

Generating assembly files enables better customization of these binaries, like allowing different sections or to define a symbol for the binary blob.

If a known symbol (via a symbol_addrs file) matches the vram of a incbin segment then it will be emitted accordingly at the top. If the symbol contains a [`name_end`](Adding-Symbols.md#name_end) property then it will be emitted after the `.incbin` (useful for Nintendo64's RSP ucodes).

Curretly there are 3 types of incbins, `textbin`, `databin` and `rodatabin`, which are intended for binary blobs of `.text`, `.data` and `.rodata` sections.

If a `textbin` section has a corresponding `databin` and/or `rodatabin` section with the same name then those will be included in the same generated assembly file.

By default the generated assembly file will be written relative to the configured [`data_path`](docs/Configuration.md#data_path). The per segment `use_src_path` option allows to tell splat that a given incbin should be relative to the [`src_path`](docs/Configuration.md#src_path) instead. This behavior can be useful to allow committing those assembly files to the repo since splat will not override them if they already exist, and still extract the binary blobs.

```yaml
- { start: 0x06C4B0, type: textbin, use_src_path: True, name: rsp/rspboot }
- [0x06C580, textbin, rsp/aspMain]

# ...

- [0x093D60, databin, rsp/aspMain]
```

## `gcc_except_table`

Used by certain compilers (like GCC) to store the Exception Handler Table (`ehtable`), used for implementing C++ exceptions.

This table contains references to addresses within functions, which normally the disassembler would automatically reject as being valid addresses. This special section bypasses that restriction by generating special labels within the functions in question. The macro used for these labels can be changed with the [`asm_ehtable_label_macro`](Configuration.md#asm_ehtable_label_macro) option.

## `eh_frame`

Used by certain compilers (like GCC) to store the Exception Handler Frame, used for implementing C++ exceptions.

This frame contains more metadata used by exceptions at runtime.

## PS2 exclusive segments

### `lit4`

`lit4` is a segment that only contains single-precision floats.

splat will try to disassemble all the data from this segment as individual floats whenever possible.

### `lit8`

`lit8` is a segment that only contains double-precision floats.

splat will try to disassemble all the data from this segment as individual doubles whenever possible.

### `ctor`

`ctor` is used by certain compilers (like MWCC) to store pointers to functions that initialize C++ global data objects.

The disassembly of this section is tweaked to avoid confusing its data with other types of data, this is because the disassembler can sometimes get confused and disassemble a pointer as a float, string, etc.

### `vtables`

`vtables` is used by certain compilers (like MWCC) to store the virtual tables of C++ classes

The disassembly of this section is tweaked to avoid confusing its data with other types of data, this is because the disassembler can sometimes get confused and disassemble a pointer as a float, string, etc.

## General segment options

All splat's segments can be passed extra options for finer configuration. Note that those extra options require to rewrite the entry using the dictionary yaml notation instead of the list one.

### `linker_section_order`

**Description:**

Allows overriding the section order used for linker script generation.

Useful when a section of a file is not between the other sections of the same type in the ROM, for example a file having its data section between other files's rodata.

Take in mind this option may need the [`check_consecutive_segment_types`](Configuration.md#check_consecutive_segment_types) yaml option to be turned off.

**Example:**

```yaml
- [0x400, data, file1]
# data ends

# rodata starts
- [0x800, rodata, file2]
- { start: 0xA00, type: data, name: file3, linker_section_order: .rodata }
- [0xC00, rodata, file4]
```

This will created `file3.data.s` within the `asm` folder, but won't be reordered in the generated linker script to be placed on the data section.

### `linker_section`

**Description:**

Allows to override the `.section` directive that will be used when generating the disassembly of the corresponding section, without needing to write an extension segment. This also affects the section name that will be used during link time.

Useful for sections with special names, like an executable section named `.start`

**Example:**

```yaml
- { start: 0x1000, type: asm, name: snmain, linker_section: .start }
- [0x1070, rdata, libc]
- [0x10A0, rdata, main_030]
```

### `ld_fill_value`

Allows to specify the value of the `FILL` statement generated for this specific top-level segment of the linker script, ignoring the global configuration.

It must be either an integer, which will be used as the parameter for the `FILL` statement, or `null`, which tells splat to not emit a `FILL` statement for this segment.

If not set, then the global configuration is used. See [ld_fill_value](Configuration.md#ld_fill_value) on the Configuration section.

Defaults to the value of the global option.

### `ld_align_segment_start`

Specify the current segment should be aligned before starting it.

This option specifies the desired alignment value, or `null` if no aligment should be imposed on the segment start.

If not set, then the global configuration is used. See [ld_align_segment_start](Configuration.md#ld_align_segment_start) on the Configuration section.

### `subalign`

Sub-alignment (in bytes) of sections.

Only works on top-level segments

`subalign` can be `null` to not force any specific alignment and use the built section's declared alignment instead.

**Example:**

```yaml
    subalign: 4
```

Defaults to the global `subalign` option.
