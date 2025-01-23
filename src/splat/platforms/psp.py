import rabbitizer


def init(target_bytes: bytes):
    rabbitizer.config.toolchainTweaks_treatJAsUnconditionalBranch = False

def user_segment():
    import spimdisasm
    user_segment = spimdisasm.UserSegmentBuilder()
    return user_segment
