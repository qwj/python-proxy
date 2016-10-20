from setuptools import setup
import os, io, re

def read(*names, **kwargs):
    with io.open(
        os.path.join(os.path.dirname(__file__), *names),
        encoding=kwargs.get("encoding", "utf8")
    ) as fp:
        return fp.read()

def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")

setup(
    name='pproxy',
    version=find_version('pproxy', '__init__.py'),
    description='Proxy server that can tunnel among remote servers by regex rules.',
    long_description=read('README.rst'),
    url='https://github.com/qwj/python-proxy',
    author='Qian Wenjie',
    author_email='qianwenjie@gmail.com',
    license='MIT',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
    ],
    keywords='proxy socks http shadowsocks cipher ssl',
    packages=['pproxy'],
    install_requires=[],
    entry_points={
        'console_scripts': [
            'pproxy=pproxy:main',
        ],
    },
)
