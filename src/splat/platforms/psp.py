import rabbitizer


def init(target_bytes: bytes):
    rabbitizer.config.toolchainTweaks_treatJAsUnconditionalBranch = False

def platform_segment():
    import spimdisasm
    platform_segment = spimdisasm.PlatformSegmentBuilder()
    return platform_segment
