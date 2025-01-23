def init(target_bytes: bytes):
    pass

def user_segment():
    import spimdisasm
    user_segment = spimdisasm.UserSegmentBuilder()
    return user_segment
