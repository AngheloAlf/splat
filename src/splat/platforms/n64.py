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

def user_segment():
    import spimdisasm
    user_segment = spimdisasm.UserSegmentBuilder()

    if options.opts.libultra_symbols:
        user_segment.n64_libultra_symbols()
    if options.opts.hardware_regs:
        user_segment.n64_hardware_registers(True, True)

    if options.opts.ique_symbols:
        user_segment.ique_libultra_symbols()
        if options.opts.hardware_regs:
            user_segment.ique_hardware_registers(True, True)

    return user_segment
