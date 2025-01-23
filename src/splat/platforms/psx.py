def init(target_bytes: bytes):
    pass

def platform_segment():
    import spimdisasm
    platform_segment = spimdisasm.PlatformSegmentBuilder()
    return platform_segment
