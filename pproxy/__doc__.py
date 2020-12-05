__title__       = "pproxy"
__license__     = "MIT"
__description__ = "Proxy server that can tunnel among remote servers by regex rules."
__keywords__    = "proxy socks http shadowsocks shadowsocksr ssr redirect pf tunnel cipher ssl udp"
__author__      = "Qian Wenjie"
__email__       = "qianwenjie@gmail.com"
__url__         = "https://github.com/qwj/python-proxy"

try:
    from setuptools_scm import get_version
    __version__ = get_version()
except Exception:
    try:
        from pkg_resources import get_distribution
        __version__ = get_distribution('pproxy').version
    except Exception:
        __version__ = 'unknown'

__all__ = ['__version__', '__description__', '__url__']
