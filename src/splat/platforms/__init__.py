from . import n64 as n64
from . import ps2 as ps2
from . import psx as psx
from . import psp as psp

def get_platform_module():
    import importlib

    from .. import __package_name__
    from ..util import options

    platform_module = importlib.import_module(
        f"{__package_name__}.platforms.{options.opts.platform}"
    )
    # platform_init = getattr(platform_module, "init")
    # platform_init(rom_bytes)

    return platform_module

def get_platform_function(func_name: str):
    platform_module = get_platform_module()
    return getattr(platform_module, func_name)
