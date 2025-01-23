from ..util import options, symbols


def init(target_bytes: bytes):
    return
    # TODO
    symbols.spim_context.fillDefaultBannedSymbols()

    if options.opts.libultra_symbols:
        symbols.spim_context.globalSegment.fillLibultraSymbols()
    if options.opts.ique_symbols:
        symbols.spim_context.globalSegment.fillIQueSymbols()
    if options.opts.hardware_regs:
        symbols.spim_context.globalSegment.fillHardwareRegs(True)

def platform_segment():
    import spimdisasm
    platform_segment = spimdisasm.PlatformSegmentBuilder()

    if options.opts.libultra_symbols:
        platform_segment.n64_libultra_symbols()
    if options.opts.hardware_regs:
        platform_segment.n64_hardware_registers(True, True)

    if options.opts.ique_symbols:
        platform_segment.ique_libultra_symbols()
        if options.opts.hardware_regs:
            platform_segment.ique_hardware_registers(True, True)

    return platform_segment
