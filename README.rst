python-proxy
============

|made-with-python| |PyPI-version| |Hit-Count| |Downloads|

.. |made-with-python| image:: https://img.shields.io/badge/Made%20with-Python-1f425f.svg
   :target: https://www.python.org/
.. |PyPI-version| image:: https://badge.fury.io/py/pproxy.svg
   :target: https://pypi.python.org/pypi/pproxy/
.. |Hit-Count| image:: http://hits.dwyl.io/qwj/python-proxy.svg
   :target: https://pypi.python.org/pypi/pproxy/
.. |Downloads| image:: https://pepy.tech/badge/pproxy
   :target: https://pepy.tech/project/pproxy

HTTP/Socks4/Socks5/Shadowsocks/ShadowsocksR/SSH/Redirect/Pf TCP/UDP asynchronous tunnel proxy implemented in Python3 asyncio.

QuickStart
----------

.. code:: rst

  $ pip3 install pproxy
  Successfully installed pproxy-1.9.5
  $ pproxy
  Serving on :8080 by http,socks4,socks5
  ^C
  $ pproxy -l ss://chacha20:abc@:8080
  Serving on :8080 by ss (chacha20-py)

Optional: (better performance with C ciphers)

.. code:: rst

  $ pip3 install pproxy[accelerated]
  Successfully installed pycryptodome-3.6.4

Apply OS system-wide proxy: (MacOS, Windows)

.. code:: rst

  $ pproxy -r ss://chacha20:abc@server_ip:8080 --sys -vv
  Serving on :8080 by http,socks4,socks5
  System proxy setting -> socks5 localhost:8080
  socks5 ::1:57345 -> ss server_ip:8080 -> slack.com:443
  socks5 ::1:57345 -> ss server_ip:8080 -> www.google.com:443
  ..... (all local traffic log) ......

Apply CLI proxy: (MacOS, Linux)

.. code:: rst

  $ export http_proxy=http://localhost:8080
  $ export https_proxy=http://localhost:8080

Run With Docker
---------------

`pproxy` Docker container has both python3 (with Cryptodome for performance optimizations) and `pypy` versions available.

Python3:

``docker run -it -p 8080:8080 mosajjal/pproxy:latest -l http://:8080 -vv``

Pypy3:

``docker run -it -p 8080:8080 mosajjal/pproxy:latest-pypy -l http://:8080 -vv``

Features
--------

- Lightweight single-thread asynchronous IO.
- Pure python, no additional library required.
- Proxy client/server for TCP/UDP.
- Schedule (load balance) among remote servers.
- Incoming traffic auto-detect.
- Tunnel/relay/backward-relay support.
- Unix domain socket support.
- User/password authentication support.
- Filter/block hostname by regex patterns.
- SSL/TLS client/server support.
- Shadowsocks OTA (One-Time-Auth_), SSR plugins.
- Statistics by bandwidth and traffic.
- PAC support for javascript configuration.
- Iptables/Pf NAT redirect packet tunnel.
- System proxy auto-setting support.
- Client/Server API provided.

.. _One-Time-Auth: https://shadowsocks.org/en/spec/one-time-auth.html

Protocols
---------

+-------------------+------------+------------+------------+------------+--------------+
| Name              | TCP server | TCP client | UDP server | UDP client | scheme       |
+===================+============+============+============+============+==============+
| http (connect)    | ✔          | ✔          |            |            | http://      |
+-------------------+            +------------+------------+------------+--------------+
| http              |            | ✔          |            |            | httponly://  |
| (get,post,etc)    |            |            |            |            | (as client)  |
+-------------------+------------+------------+------------+------------+--------------+
| https             | ✔          | ✔          |            |            | http+ssl://  |
+-------------------+------------+------------+------------+------------+--------------+
| socks4            | ✔          | ✔          |            |            | socks4://    |
+-------------------+------------+------------+------------+------------+--------------+
| socks5            | ✔          | ✔          | ✔ udp-only | ✔ udp-only | socks5://    |
+-------------------+------------+------------+------------+------------+--------------+
| socks5 over TLS   | ✔          | ✔          |            |            | socks5+ssl://|
+-------------------+------------+------------+------------+------------+--------------+
| shadowsocks       | ✔          | ✔          | ✔          | ✔          | ss://        |
+-------------------+------------+------------+------------+------------+--------------+
| shadowsocks aead  | ✔          | ✔          |            |            | ss://        |
+-------------------+------------+------------+------------+------------+--------------+
| shadowsocksR      | ✔          | ✔          |            |            | ssr://       |
+-------------------+------------+------------+------------+------------+--------------+
| ssh tunnel        |            | ✔          |            |            | ssh://       |
+-------------------+------------+------------+------------+------------+--------------+
| iptables nat      | ✔          |            |            |            | redir://     |
+-------------------+------------+------------+------------+------------+--------------+
| pfctl nat (macos) | ✔          |            |            |            | pf://        |
+-------------------+------------+------------+------------+------------+--------------+
| echo              | ✔          |            | ✔          |            | echo://      |
+-------------------+------------+------------+------------+------------+--------------+
| tunnel            | ✔          | ✔          | ✔          | ✔          | tunnel://    |
| (raw socket)      |            |            |            |            | tunnel{ip}://|
+-------------------+------------+------------+------------+------------+--------------+
| websocket         | ✔          | ✔          |            |            | ws://        |
| (simple tunnel)   |            |            |            |            | ws{dst_ip}://|
+-------------------+------------+------------+------------+------------+--------------+
| xxx over TLS      | ✔          | ✔          |            |            | xxx+ssl://   |
+-------------------+------------+------------+------------+------------+--------------+
| AUTO DETECT       | ✔          |            | ✔          |            | a+b+c+d://   |
+-------------------+------------+------------+------------+------------+--------------+

Scheduling Algorithms
---------------------

+-------------------+------------+------------+------------+------------+
| Name              | TCP        | UDP        | Parameter  | Default    |
+===================+============+============+============+============+
| first_available   | ✔          | ✔          | -s fa      | ✔          |
+-------------------+------------+------------+------------+------------+
| round_robin       | ✔          | ✔          | -s rr      |            |
+-------------------+------------+------------+------------+------------+
| random_choice     | ✔          | ✔          | -s rc      |            |
+-------------------+------------+------------+------------+------------+
| least_connection  | ✔          |            | -s lc      |            |
+-------------------+------------+------------+------------+------------+

Requirement
-----------

pycryptodome_ is an optional library to enable faster (C version) cipher. **pproxy** has many built-in pure python ciphers. They are lightweight and stable, but slower than C ciphers. After speedup with PyPy_, pure python ciphers can get similar performance as C version. If the performance is important and don't have PyPy_, install pycryptodome_ instead.

asyncssh_ is an optional library to enable ssh tunnel client support.

These are some performance benchmarks between Python and C ciphers (dataset: 8M):

+---------------------+----------------+
| chacha20-c          | 0.64 secs      |
+---------------------+----------------+
| chacha20-py (pypy3) | 1.32 secs      |
+---------------------+----------------+
| chacha20-py         | 48.86 secs     |
+---------------------+----------------+

PyPy3 Quickstart:

.. code:: rst

  $ pypy3 -m ensurepip
  $ pypy3 -m pip install asyncio pproxy

.. _pycryptodome: https://pycryptodome.readthedocs.io/en/latest/src/introduction.html
.. _asyncssh: https://asyncssh.readthedocs.io/en/latest/
.. _PyPy: http://pypy.org

Usage
-----

.. code:: rst

  $ pproxy -h
  usage: pproxy [-h] [-l LISTEN] [-r RSERVER] [-ul ULISTEN] [-ur URSERVER]
                [-b BLOCK] [-a ALIVED] [-v] [--ssl SSLFILE] [--pac PAC]
                [--get GETS] [--sys] [--test TESTURL] [--version]

  Proxy server that can tunnel among remote servers by regex rules. Supported
  protocols: http,socks4,socks5,shadowsocks,shadowsocksr,redirect,pf,tunnel

  optional arguments:
    -h, --help        show this help message and exit
    -l LISTEN         tcp server uri (default: http+socks4+socks5://:8080/)
    -r RSERVER        tcp remote server uri (default: direct)
    -ul ULISTEN       udp server setting uri (default: none)
    -ur URSERVER      udp remote server uri (default: direct)
    -b BLOCK          block regex rules
    -a ALIVED         interval to check remote alive (default: no check)
    -s {fa,rr,rc,lc}  scheduling algorithm (default: first_available)
    -v                print verbose output
    --ssl SSLFILE     certfile[,keyfile] if server listen in ssl mode
    --pac PAC         http PAC path
    --get GETS        http custom {path,file}
    --sys             change system proxy setting (mac, windows)
    --test TEST       test this url for all remote proxies and exit
    --version         show program's version number and exit

  Online help: <https://github.com/qwj/python-proxy>

URI Syntax
----------

.. code:: rst

  {scheme}://[{cipher}@]{netloc}/[@{localbind}][,{plugins}][?{rules}][#{auth}]

- scheme

  - Currently supported scheme: http, socks, ss, ssl, secure. You can use + to link multiple protocols together.

    +----------+-----------------------------+
    | http     | http protocol (CONNECT)     |
    +----------+-----------------------------+
    | httponly | http protocol (GET/POST)    |
    +----------+-----------------------------+
    | socks4   | socks4 protocol             |
    +----------+-----------------------------+
    | socks5   | socks5 protocol             |
    +----------+-----------------------------+
    | ss       | shadowsocks protocol        |
    +----------+-----------------------------+
    | ssr      | shadowsocksr (SSR) protocol |
    +----------+-----------------------------+
    | ssh      | ssh client tunnel           |
    +----------+-----------------------------+
    | redir    | redirect (iptables nat)     |
    +----------+-----------------------------+
    | pf       | pfctl (macos pf nat)        |
    +----------+-----------------------------+
    | ssl      | unsecured ssl/tls (no cert) |
    +----------+-----------------------------+
    | secure   | secured ssl/tls (cert)      |
    +----------+-----------------------------+
    | tunnel   | raw connection              |
    +----------+-----------------------------+
    | ws       | websocket connection        |
    +----------+-----------------------------+
    | echo     | echo-back service           |
    +----------+-----------------------------+
    | direct   | direct connection           |
    +----------+-----------------------------+

  - "http://" accepts GET/POST/CONNECT as server, sends CONNECT as client. "httponly://" sends "GET/POST" as client, works only on http traffic.

  - Valid schemes: http://, http+socks4+socks5://, http+ssl://, ss+secure://, http+socks5+ss://

  - Invalid schemes: ssl://, secure://

- cipher

  - Cipher's format: "cipher_name:cipher_key". Cipher can be base64-encoded. So cipher string with "YWVzLTEyOC1nY206dGVzdA==" is equal to "aes-128-gcm:test".

  - Full cipher support list:

    +-----------------+------------+-----------+-------------+
    | Cipher          | Key Length | IV Length | Score (0-5) |
    +=================+============+===========+=============+
    | table-py        | any        | 0         | 0 (lowest)  |
    +-----------------+------------+-----------+-------------+
    | rc4             | 16         | 0         | 0 (lowest)  |
    +-----------------+------------+-----------+-------------+
    | rc4-md5         | 16         | 16        | 0.5         |
    +-----------------+------------+-----------+-------------+
    | chacha20        | 32         | 8         | 5 (highest) |
    +-----------------+------------+-----------+-------------+
    | chacha20-ietf   | 32         | 12        | 5           |
    +-----------------+------------+-----------+-------------+
    | chacha20-ietf-  |            |           |             |
    | poly1305-py     | 32         | 32        | AEAD        |
    +-----------------+------------+-----------+-------------+
    | salsa20         | 32         | 8         | 4.5         |
    +-----------------+------------+-----------+-------------+
    | aes-128-cfb     | 16         | 16        | 3           |
    |                 |            |           |             |
    | aes-128-cfb8    |            |           |             |
    |                 |            |           |             |
    | aes-128-cfb1-py |            |           | slow        |
    +-----------------+------------+-----------+-------------+
    | aes-192-cfb     | 24         | 16        | 3.5         |
    |                 |            |           |             |
    | aes-192-cfb8    |            |           |             |
    |                 |            |           |             |
    | aes-192-cfb1-py |            |           | slow        |
    +-----------------+------------+-----------+-------------+
    | aes-256-cfb     | 32         | 16        | 4.5         |
    |                 |            |           |             |
    | aes-256-ctr     |            |           |             |
    |                 |            |           |             |
    | aes-256-ofb     |            |           |             |
    |                 |            |           |             |
    | aes-256-cfb8    |            |           |             |
    |                 |            |           |             |
    | aes-256-cfb1-py |            |           | slow        |
    +-----------------+------------+-----------+-------------+
    | aes-256-gcm     | 32         | 32        | AEAD        |
    |                 |            |           |             |
    | aes-192-gcm     | 24         | 24        | AEAD        |
    |                 |            |           |             |
    | aes-128-gcm     | 16         | 16        | AEAD        |
    +-----------------+------------+-----------+-------------+
    | camellia-256-cfb| 32         | 16        | 4           |
    |                 |            |           |             |
    | camellia-192-cfb| 24         | 16        | 4           |
    |                 |            |           |             |
    | camellia-128-cfb| 16         | 16        | 4           |
    +-----------------+------------+-----------+-------------+
    | bf-cfb          | 16         | 8         | 1           |
    +-----------------+------------+-----------+-------------+
    | cast5-cfb       | 16         | 8         | 2.5         |
    +-----------------+------------+-----------+-------------+
    | des-cfb         | 8          | 8         | 1.5         |
    +-----------------+------------+-----------+-------------+
    | rc2-cfb-py      | 16         | 8         | 2           |
    +-----------------+------------+-----------+-------------+
    | idea-cfb-py     | 16         | 8         | 2.5         |
    +-----------------+------------+-----------+-------------+
    | seed-cfb-py     | 16         | 16        | 2           |
    +-----------------+------------+-----------+-------------+

  - *pproxy* ciphers have pure python implementations. Program will switch to C cipher if there is C implementation available within pycryptodome_. Otherwise, use pure python cipher.

  - AEAD ciphers use additional payload after each packet. The underlying protocol is different. Specifications: AEAD_.

  - Some pure python ciphers (aes-256-cfb1-py) is quite slow, and is not recommended to use without PyPy speedup. Try install pycryptodome_ and use C version cipher instead.

  - To enable OTA encryption with shadowsocks, add '!' immediately after cipher name.

- netloc

  - It can be "hostname:port" or "/unix_domain_socket". If the hostname is empty, server will listen on all interfaces.

  - Valid netloc: localhost:8080, 0.0.0.0:8123, /tmp/domain_socket, :8123

- localbind

  - It can be "@in" or @ipv4_address or @ipv6_address

  - Valid localbind: @in, @192.168.1.15, @::1

- plugins

  - It can be multiple plugins joined by ",". Supported plugins: plain, origin, http_simple, tls1.2_ticket_auth, verify_simple, verify_deflate

  - Valid plugins: /,tls1.2_ticket_auth,verify_simple

- rules

  - The filename that contains regex rules

- auth

  - The username, colon ':', and the password

URIs can be joined by "__" to indicate tunneling by relay. For example, ss://1.2.3.4:1324__http://4.5.6.7:4321 make remote connection to the first shadowsocks proxy server, and then tunnel to the second http proxy server.

.. _AEAD: http://shadowsocks.org/en/spec/AEAD-Ciphers.html

Client API
----------

- TCP Client API

  .. code:: rst

    import asyncio, pproxy

    async def test_tcp(proxy_uri):
        conn = pproxy.Connection(proxy_uri)
        reader, writer = await conn.tcp_connect('google.com', 80)
        writer.write(b'GET / HTTP/1.1\r\n\r\n')
        data = await reader.read(1024*16)
        print(data.decode())

    asyncio.run(test_tcp('ss://aes-256-cfb:password@remote_host:remote_port'))

- UDP Client API

  .. code:: rst

    import asyncio, pproxy

    async def test_udp(proxy_uri):
        conn = pproxy.Connection(proxy_uri)
        answer = asyncio.Future()
        await conn.udp_sendto('8.8.8.8', 53, b'hello the world', answer.set_result)
        await answer
        print(answer.result())

    asyncio.run(test_udp('ss://chacha20:password@remote_host:remote_port'))

Server API
----------

- Server API example:

  .. code:: rst

    import asyncio
    import pproxy

    server = pproxy.Server('ss://0.0.0.0:1234')
    remote = pproxy.Connection('ss://1.2.3.4:5678')
    args = dict( rserver = [remote],
                 verbose = print )

    loop = asyncio.get_event_loop()
    handler = loop.run_until_complete(server.start_server(args))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print('exit!')

    handler.close()
    loop.run_until_complete(handler.wait_closed())
    loop.run_until_complete(loop.shutdown_asyncgens())
    loop.close()


Examples
--------

- Regex rule

  Define regex file "rules" as follow:

  .. code:: rst

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

  Then start *pproxy*

  .. code:: rst

    $ pproxy -r http://aa.bb.cc.dd:8080?rules -vv
    Serving on :8080 by http,socks4,socks5
    http ::1:57768 -> http aa.bb.cc.dd:8080 -> www.googleapis.com:443
    http ::1:57772 -> www.yahoo.com:80
    socks4 ::1:57770 -> http aa.bb.cc.dd:8080 -> www.youtube.com:443

  *pproxy* will serve incoming traffic by http/socks4/socks5 auto-detect protocol, redirect all google traffic to http proxy aa.bb.cc.dd:8080, and visit all other traffic directly from local.

- Use cipher

  Add cipher encryption to make sure data can't be intercepted. Run *pproxy* locally as:

  .. code:: rst

    $ pproxy -l ss://:8888 -r ss://chacha20:cipher_key@aa.bb.cc.dd:12345 -vv

  Next, run pproxy.py remotely on server "aa.bb.cc.dd". The base64 encoded string of "chacha20:cipher_key" is also supported:

  .. code:: rst

    $ pproxy -l ss://chacha20:cipher_key@:12345

  The same as:

  .. code:: rst

    $ pproxy -l ss://Y2hhY2hhMjA6Y2lwaGVyX2tleQ==@:12345

  The traffic between local and aa.bb.cc.dd is encrypted by stream cipher Chacha20 with secret key "cipher_key".

- Unix domain socket

  A more complex example:

  .. code:: rst

    $ pproxy -l ss://salsa20!:complex_cipher_key@/tmp/pproxy_socket -r http+ssl://domain1.com:443#username:password

  *pproxy* listen on the unix domain socket "/tmp/pproxy_socket" with cipher "salsa20" and key "complex_cipher_key". OTA packet protocol is enabled by adding ! after cipher name. The traffic is tunneled to remote https proxy with simple http authentication.

- SSL/TLS server

  If you want to listen in SSL/TLS, you must specify ssl certificate and private key files by parameter "--ssl":

  .. code:: rst

    $ pproxy -l http+ssl://0.0.0.0:443 -l http://0.0.0.0:80 --ssl server.crt,server.key --pac /autopac

  *pproxy* listen on both 80 HTTP and 443 HTTPS ports, use the specified SSL/TLS certificate and private key files. The "--pac" enable PAC feature, so you can put "https://yourdomain.com/autopac" path in your device's auto-configure url.

  Simple guide for generating self-signed ssl certificates:

  .. code:: rst

    $ openssl genrsa -des3 -out server.key 1024
    $ openssl req -new -key server.key -out server.csr
    $ cp server.key server.key.org
    $ openssl rsa -in server.key.org -out server.key
    $ openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

- SSR plugins

  ShadowsocksR example with plugin "tls1.2_ticket_auth" to emulate common tls traffic:

  .. code:: rst

    $ pproxy -l ssr://chacha20:mypass@0.0.0.0:443/,tls1.2_ticket_auth,verify_simple

- Local bind ip

  If you want to route the traffic by different local bind, use the @localbind URI syntax. For example, server has three ip interfaces: 192.168.1.15, 111.0.0.1, 112.0.0.1. You want to route traffic matched by "rule1" to 111.0.0.2 and traffic matched by "rule2" to 222.0.0.2, and the remaining traffic directly:

  .. code:: rst

    $ pproxy -l ss://:8000/@in -r ss://111.0.0.2:8000/@111.0.0.1?rule1 -r ss://222.0.0.2:8000/@222.0.0.1?rule2

- Redirect/Pf protocol

  IPTable NAT redirect example (Ubuntu):

  .. code:: rst

    $ sudo iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports 5555
    $ pproxy -l redir://:5555 -r http://remote_http_server:3128 -vv

  The above example illustrates how to redirect all local output tcp traffic with destination port 80 to localhost port 5555 listened by **pproxy**, and then tunnel the traffic to remote http proxy.

  PF redirect example (MacOS):

  .. code:: rst

    $ sudo pfctl -ef /dev/stdin
    rdr pass on lo0 inet proto tcp from any to any port 80 -> 127.0.0.1 port 8080
    pass out on en0 route-to lo0 inet proto tcp from any to any port 80 keep state
    ^D
    $ sudo pproxy -l pf://:8080 -r socks5://remote_socks5_server:1324 -vv

  Make sure **pproxy** runs in root mode (sudo), otherwise it cannot redirect pf packet.

- Relay tunnel

  Relay tunnel example:

  .. code:: rst

    $ pproxy -r http://server1__ss://server2__socks://server3

  *pproxy* will connect to server1 first, tell server1 connect to server2, and tell server2 connect to server3, and make real traffic by server3.

- Raw connection tunnel

  TCP raw connection tunnel example:

  .. code:: rst

    $ pproxy -l tunnel{google.com}://:80
    $ curl -H "Host: google.com" http://localhost

  UDP dns tunnel example:

  .. code:: rst

    $ pproxy -ul tunnel{8.8.8.8}://:53
    $ nslookup google.com localhost

- UDP more complicated example

  Run the shadowsocks udp proxy on remote machine:

  .. code:: rst

    $ pproxy -ul ss://remote_server:13245

  Run the commands on local machine:

  .. code:: rst

    $ pproxy -ul tunnel{8.8.8.8}://:53 -ur ss://remote_server:13245 -vv
    UDP tunnel 127.0.0.1:60573 -> ss remote_server:13245 -> 8.8.8.8:53
    UDP tunnel 127.0.0.1:60574 -> ss remote_server:13245 -> 8.8.8.8:53
    ...
    $ nslookup google.com localhost

- Load balance example

  Specify multiple -r server, and a scheduling algorithm (rr = round_robin, rc = random_choice, lc = least_connection):

  .. code:: rst

    $ pproxy -r http://server1 -r ss://server2 -r socks5://server3 -s rr -vv
    http ::1:42356 -> http server1 -> google.com:443
    http ::1:42357 -> ss server2 -> google.com:443
    http ::1:42358 -> socks5 server3 -> google.com:443
    http ::1:42359 -> http server1 -> google.com:443
    ...
    $ pproxy -ul tunnel://:53 -ur tunnel://8.8.8.8:53 -ur tunnel://8.8.4.4:53 -s rc -vv
    UDP tunnel ::1:35378 -> tunnel 8.8.8.8:53
    UDP tunnel ::1:35378 -> tunnel 8.8.4.4:53
    ...

- WebSocket example

  WebSocket protocol is similar to Tunnel protocol. It is raw and doesn't support any proxy function. It can connect to other proxy like Tunnel protocol.

  First run pproxy on remote machine:

  .. code:: rst

    $ pproxy -l ws://:80 -r tunnel:///tmp/myproxy -v
    $ pproxy -l ss://chacha20:abc@/tmp/myproxy -v

  Run pproxy on local machine:

  .. code:: rst

    $ pproxy -l tunnel://:1234 -r ws://remote_ip:80 -vv

  Then port :1234 on local machine is connected to the /tmp/myproxy on remote machine by WebSocket tunnel. You can specify any proxy protocol details on /tmp/myproxy.

  It is a good practice to use some CDN in the middle of local/remote machines. CDN with WebSocket support can hide remote machine's real IP from public.

- Backward proxy

  Sometimes, the proxy server hides behind an NAT router and doesn't have a public ip. The client side has a public ip "client_ip". Backward proxy feature enables the server to connect backward to client and wait for proxy requests.

  Run **pproxy** client as follows:

  .. code:: rst

    $ pproxy -l http://:8080 -r http+in://:8081 -v

  Run **pproxy** server as follows:

  .. code:: rst

    $ pproxy -l http+in://client_ip:8081

  Server connects to client_ip:8081 and waits for client proxy requests. The protocol http specified is just an example. It can be any protocol and cipher **pproxy** supports. The scheme "**in**" should exist in URI to inform **pproxy** that it is a backward proxy.

- SSH client tunnel

  SSH client tunnel support is enabled by installing additional library asyncssh_. After "pip3 install asyncssh", you can specify "**ssh**" as scheme to proxy via ssh client tunnel.

  .. code:: rst

    $ pproxy -l http://:8080 -r ssh://remote_server.com/#login:password

  If a client private key is used to authenticate, put double colon "::" between login and private key path.

  .. code:: rst

    $ pproxy -l http://:8080 -r ssh://remote_server.com/#login::private_key_path

  SSH connection known_hosts feature is disabled by default.


Projects
--------

+ `python-esp <https://github.com/qwj/python-esp>`_ - Pure python VPN (IPSec,IKE,IKEv2,L2TP)
+ `shadowproxy <https://github.com/guyingbo/shadowproxy>`_ - Another awesome proxy implementation by guyingbo

