python-proxy
===========

HTTP/Socks5/Shadowsocks Asynchronous Tunnel Proxy implemented in Python 3.6 asyncio.

Python 3.6
-----------

*Python 3.5* added new syntax *async def* and *await* to make asyncio programming easier. *Python 3.6* added new syntax *formatted string literals*. This utility is to demonstrate these new syntax and is also fully ready for production usage.

Installation
-----------

    $ sudo pip3 install pproxy

Features
-----------

- Automatically detect incoming protocol: HTTP/Socks5/Shadowsocks.
- Specify remote servers for outcoming protocol.
- Unix path support for communicating locally.
- Basic authentication method for HTTP/Socks5/Shadowsocks.
- Regex pattern file support for redirecting/blocking by hostname.
- SSL connection support to prevent Man-In-The-Middle attack.
- Many ciphers support to keep communication securely. (chacha20, salsa20, aes-256-cfb, etc)
- Basic statistics for bandwidth and total traffic by client/hostname.
- PAC support for automatically javascript configuration.

Usage
-----------

    $ pproxy -h
    usage: pproxy [-h] [-i LISTEN] [-r RSERVER] [-b BLOCK] [-v] [--ssl SSLFILE] [--pac PAC] [--version]
    
    Proxy server that can tunnel among remote servers by regex rules. Supported
    protocols: http,socks,shadowsocks
    
    optional arguments:
      -h, --help     show this help message and exit
      -i LISTEN      proxy server setting uri (default: http+socks://:8080/)
      -r RSERVER     remote server setting uri (default: direct)
      -b BLOCK       block regex rules
      -v             print verbose output
      --ssl SSLFILE  certfile[,keyfile] if server listen in ssl mode
      --pac PAC      http pac file path
      --version      show program's version number and exit
    
    Online help: <https://github.com/qwj/python-proxy>

Uri Syntax
-----------

{scheme}://[{cipher}@]{netloc}[?{rules}][#{auth}]

- scheme
    - Currently supported scheme: http, socks, ss, ssl, secure. You can use + to add multiple protocols together.
        - http - http protocol
        - socks - socks5 protocol
        - ss - shadowsocks protocol
        - ssl - communicate in (unsecured) ssl
        - secure - comnunicate in (secured) ssl
    - Valid schemes are: http://, http+socks://, http+ssl://, ss+secure://
    - Invalid schemes are: ssl://, secure://
- cipher
    - Cipher is consisted by cipher name, colon ':' and cipher key.
    - Full cipher list:  table, rc4, rc4-md5, chacha20, salsa20, aes-128-cfb, aes-192-cfb, aes-256-cfb, bf-cfb, cast5-fb, des-cfb
- netloc
    - It can be "hostname:port" or "/unix_path". If the hostname is empty, server will listen on all interfaces.
- rules
    - The filename that contains regex rules
- auth
    - The username, colon ':', and the password

Examples
-----------

We can define file "rules" as follow:

    #google domains
    (?:.+\.)?google.*\.com
    (?:.+\.)?gstatic\.com
    (?:.+\.)?gmail\.com
    (?:.+\.)?ntp\.org
    (?:.+\.)?glpals\.com
    (?:.+\.)?akamai.*\.net
    (?:.+\.)?ggpht\.com
    (?:.+\.)?android\.com
    (?:.+\.)?gvt1\.com
    (?:.+\.)?youtube.*\.com
    (?:.+\.)?ytimg\.com
    (?:.+\.)?goo\.gl
    (?:.+\.)?youtu\.be
    (?:.+\.)?google\..+

Then start the pproxy

    pproxy -i http+socks://:8080 -r http://aa.bb.cc.dd:8080?rules -v
    
With these parameters, this utility will serve incoming traffic by either http/socks5 protocol, redirect all google traffic to http proxy aa.bb.cc.dd:8080, and visit all other traffic locally.

To bridge two servers, add cipher key to ensure data can't be intercepted. First, run pproxy locally

    pproxy -i ss://:8888 -r ss://chacha20:cipher_key@aa.bb.cc.dd:12345 -v
    
Next, run pproxy.py remotely on server "aa.bb.cc.dd"

    pproxy -i ss://chacha20:cipher_key@:12345
    
By doing this, the traffic between local and aa.bb.cc.dd is encrypted by stream cipher Chacha20 with key "This is a cipher key". If target hostname is not in "rules", traffic will go through locally. Otherwise, traffic will go through the remote server by encryption.

