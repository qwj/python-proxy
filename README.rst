python-proxy
===========

HTTP/Socks/Shadowsocks asynchronous tunnel proxy implemented in Python 3.6 asyncio.

Features
-----------

- Single-thread asynchronous IO with high availability and scalability.
- Lightweight (~500 lines) and powerful by leveraging python builtin *asyncio* library.
- Automatically detect incoming traffic: HTTP/Socks/Shadowsocks.
- Specify multiple remote servers for outcoming traffic: HTTP/Socks/Shadowsocks.
- Unix domain socket support for communicating locally.
- Basic authentication support for all three protocols.
- Regex pattern file support to route/block by hostname matching.
- SSL connection support to prevent Man-In-The-Middle attack.
- Encryption cipher support to keep communication secure. (chacha20, aes-256-cfb, etc)
- Shadowsocks OTA (One-Time-Auth_) experimental feature support.
- Basic statistics for bandwidth and total traffic by client/hostname.
- PAC support for automatically javascript configuration.

.. _One-Time-Auth: https://shadowsocks.org/en/spec/one-time-auth.html

Python 3.6
-----------

*Python 3.5* added new syntax **async def** and **await** to make asyncio programming easier. *Python 3.6* added new syntax **formatted string literals**. This tool is to demonstrate these new syntax, so the minimal Python requirement is **3.6**. With new syntax, it is easy to implement so many features in a short number of lines, and is also fully ready for production usage.

Installation
-----------

    $ pip3 install pproxy

Requirement
-----------

pycryptodome_ is the optional required library to enable cipher encryption support. Without installing this, you can still use pproxy with no encryption.

.. _pycryptodome: https://pycryptodome.readthedocs.io/en/latest/src/introduction.html

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

URI Syntax
-----------

{scheme}://[{cipher}@]{netloc}[?{rules}][#{auth}]

- scheme
    - Currently supported scheme: http, socks, ss, ssl, secure. You can use + to link multiple protocols together.

        :http: http protocol
        :socks: socks5 protocol
        :ss: shadowsocks protocol
        :ssl: communicate in (unsecured) ssl
        :secure: comnunicate in (secured) ssl

    - Valid schemes: http://, http+socks://, http+ssl://, ss+secure://, http+socks+ss://
    - Invalid schemes: ssl://, secure://
- cipher
    - Cipher is consisted by cipher name, colon ':' and cipher key.
    - Full supported cipher list:

        +------------+------------+-----------+-------------+
        | Cipher     | Key Length | IV Length | Security    |
        +============+============+===========+=============+
        | table      | any        | 0         | 0 (lowest)  |
        +------------+------------+-----------+-------------+
        | rc4        | 16         | 0         | 0 (lowest)  |
        +------------+------------+-----------+-------------+
        | rc4-md5    | 16         | 16        | 0.5         |
        +------------+------------+-----------+-------------+ 
        | chacha20   | 32         | 8         | 5 (highest) |
        +------------+------------+-----------+-------------+
        | salsa20    | 32         | 8         | 5 (highest) |
        +------------+------------+-----------+-------------+
        | aes-128-cfb| 16         | 16        | 3           |
        +------------+------------+-----------+-------------+
        | aes-192-cfb| 24         | 16        | 3.5         |
        +------------+------------+-----------+-------------+
        | aes-256-cfb| 32         | 16        | 4.5         |
        +------------+------------+-----------+-------------+
        | bf-cfb     | 16         | 8         | 2           |
        +------------+------------+-----------+-------------+
        | cast5-cfb  | 16         | 8         | 2.5         |
        +------------+------------+-----------+-------------+
        | des-cfb    | 8          | 8         | 1           |
        +------------+------------+-----------+-------------+

    - To enable OTA encryption with shadowsocks, add '!' immediately after cipher name.
- netloc
    - It can be "hostname:port" or "/unix_domaon_path". If the hostname is empty, server will listen on all interfaces.
    - Valid netloc: localhost:8080, 0.0.0.0:8123, /tmp/domain_socket, :8123
- rules
    - The filename that contains regex rules
- auth
    - The username, colon ':', and the password

Examples
-----------

We can define file "rules" as follow:

    | #google domains
    | (?:.+\.)?google.*\.com
    | (?:.+\.)?gstatic\.com
    | (?:.+\.)?gmail\.com
    | (?:.+\.)?ntp\.org
    | (?:.+\.)?glpals\.com
    | (?:.+\.)?akamai.*\.net
    | (?:.+\.)?ggpht\.com
    | (?:.+\.)?android\.com
    | (?:.+\.)?gvt1\.com
    | (?:.+\.)?youtube.*\.com
    | (?:.+\.)?ytimg\.com
    | (?:.+\.)?goo\.gl
    | (?:.+\.)?youtu\.be
    | (?:.+\.)?google\..+

Then start the pproxy

    | $ pproxy -i http+socks://:8080 -r http://aa.bb.cc.dd:8080?rules -v
    | http www.googleapis.com:443 -> http aa.bb.cc.dd:8080
    | socks www.youtube.com:443 -> http aa.bb.cc.dd:8080
    | http www.yahoo.com:80
    | DIRECT: 1 (0.5K/s,1.2M/s)   PROXY: 2 (24.3K/s,1.9M/s)

With these parameters, this utility will serve incoming traffic by either http/socks5 protocol, redirect all google traffic to http proxy aa.bb.cc.dd:8080, and visit all other traffic locally.

To bridge two servers, add cipher encryption to ensure data can't be intercepted. First, run pproxy locally

    $ pproxy -i ss://:8888 -r ss://chacha20:cipher_key@aa.bb.cc.dd:12345 -v
    
Next, run pproxy.py remotely on server "aa.bb.cc.dd"

    $ pproxy -i ss://chacha20:cipher_key@:12345
    
By doing this, the traffic between local and aa.bb.cc.dd is encrypted by stream cipher Chacha20 with key "cipher_key". If target hostname is not matched by regex file "rules", traffic will go through locally. Otherwise, traffic will go through the remote server by encryption.

A more complex example:

    $ pproxy -i ss://salsa20!:complex_cipher_key@/tmp/pproxy_socket -r http+ssl://domain1.com:443#username:password

It listen on the unix domain socket /tmp/pproxy_socket, and use cipher name salsa20, cipher key "complex_cipher_key", and enable explicit OTA encryption for shadowsocks protocol. The traffic is tunneled to remote https proxy with simple authentication. If OTA mode is not specified, server will allow both non-OTA and OTA traffic. If specified OTA mode, server only allow OTA client to connect.

If you want to listen in SSL, you must specify ssl certificate and private key files by parameter "--ssl", there is an example:

    $ pproxy -i http+ssl://0.0.0.0:443 -i http://0.0.0.0:80 --ssl server.crt,server.key --pac /autopac

It listen on both 80 HTTP and 443 HTTPS ports, use the specified certificate and private key files. The "--pac" enable PAC support, so you can put https://yourdomain.com/autopac in your device's auto-configure url.


